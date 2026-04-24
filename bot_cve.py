import json
import os
import re
import time
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from groq import Groq
from supabase import create_client

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK_URL")

AUTO_PUBLISH = os.getenv("AUTO_PUBLISH", "false").strip().lower() in {"1", "true", "yes", "y"}

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_URL_TEMPLATE = os.getenv("NVD_URL_TEMPLATE", "https://nvd.nist.gov/vuln/detail/{cve_id}")

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
ALLOWED_VECTOR = {"Rede", "Local", "Adjacente", "Físico", "Desconhecido"}
ALLOWED_COMPLEXITY = {"Baixa", "Média", "Alta", "Desconhecida"}
ALLOWED_AUTH = {"Nenhuma", "Usuário", "Administrador", "Desconhecida"}

HEADERS = {
    "User-Agent": "cve-news-bot/2.0",
    "Accept": "application/json"
}

supabase = None
groq_client = None
session = requests.Session()
session.headers.update(HEADERS)


def init_clients():
    global supabase, groq_client

    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("SUPABASE não configurado")

    supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

    if GROQ_API_KEY:
        groq_client = Groq(api_key=GROQ_API_KEY)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def normalizar_texto(valor, padrao=""):
    if valor is None:
        return padrao
    if isinstance(valor, str):
        return valor.strip()
    return str(valor).strip()


def severity_from_cvss(cvss):
    try:
        score = float(cvss)
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
    except:
        pass
    return "info"


def clean_json_text(raw):
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)

    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1:
        raw = raw[start:end + 1]

    return raw.strip()


def validar_analise(data, cve_id, cvss=None):
    if not isinstance(data, dict):
        return None

    title = normalizar_texto(data.get("title"))
    description_pt = normalizar_texto(data.get("description_pt"))
    severity = normalizar_texto(data.get("severity"), severity_from_cvss(cvss)).lower()

    if not title or not description_pt:
        return None

    return {
        "title": title[:80],
        "description_pt": description_pt,
        "severity": severity,
        "tags": data.get("tags", []),
        "vetor": data.get("vetor", "Desconhecido"),
        "complexidade": data.get("complexidade", "Desconhecida"),
        "autenticacao": data.get("autenticacao", "Desconhecida"),
        "exploit_facilidade": data.get("exploit_facilidade", "Não confirmado"),
    }


def extrair_cvss(metrics):
    try:
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics:
                return metrics[key][0]["cvssData"]["baseScore"]
    except:
        pass
    return None


def extrair_descricao(descriptions):
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value")
    return "Sem descrição"


def montar_item_nvd(cve):
    return {
        "id": cve.get("id"),
        "summary": extrair_descricao(cve.get("descriptions", [])),
        "cvss": extrair_cvss(cve.get("metrics", {})),
        "published": cve.get("published")
    }


def analisar_com_llama(cve_id, summary, cvss=None):
    if not groq_client:
        return {
            "title": f"{cve_id}",
            "description_pt": summary,
            "severity": severity_from_cvss(cvss),
            "tags": [],
            "vetor": "Desconhecido",
            "complexidade": "Desconhecida",
            "autenticacao": "Desconhecida",
            "exploit_facilidade": "Não confirmado"
        }

    prompt = f"""
CVE: {cve_id}
CVSS: {cvss}
Resumo: {summary}

Responda JSON:
{{
"title": "...",
"description_pt": "...",
"severity": "critical|high|medium|low|info",
"tags": [],
"vetor": "...",
"complexidade": "...",
"autenticacao": "...",
"exploit_facilidade": "..."
}}
"""

    try:
        r = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )

        raw = clean_json_text(r.choices[0].message.content)
        return validar_analise(json.loads(raw), cve_id, cvss)

    except Exception as e:
        print("Erro IA:", e)
        return None


def cve_ja_existe(cve_id):
    res = supabase.table("news_articles").select("id").eq("cve_id", cve_id).execute()
    return bool(res.data)


def salvar_no_supabase(analise, cve_id, cve, published=False):
    payload = {
        "title": analise["title"],
        "description_pt": analise["description_pt"],
        "severity": analise["severity"],
        "tags": analise.get("tags", []),
        "vetor": analise.get("vetor"),
        "complexidade": analise.get("complexidade"),
        "autenticacao": analise.get("autenticacao"),
        "exploit_facilidade": analise.get("exploit_facilidade"),
        "original_url": NVD_URL_TEMPLATE.format(cve_id=cve_id),
        "cve_id": cve_id,
        "published_at": cve.get("published") or now_iso(),
        "published": bool(published),
    }

    return supabase.table("news_articles").insert(payload).execute()


def enviar_discord(cve_id, analise):
    if not DISCORD_WEBHOOK:
        return

    msg = f"""
📢 NOVA CVE: {cve_id}
{analise['title']}

{analise['description_pt']}

{NVD_URL_TEMPLATE.format(cve_id=cve_id)}
"""

    session.post(DISCORD_WEBHOOK, json={"content": msg})


def coletar_cves():
    print("📡 Coletando CVEs do NVD...")

    params = {
        "resultsPerPage": 20,
        "startIndex": 0,
        "noRejected": "true"
    }

    resp = session.get(NVD_API_URL, params=params, timeout=30)
    resp.raise_for_status()

    data = resp.json()
    vulns = data.get("vulnerabilities", [])

    return [montar_item_nvd(v["cve"]) for v in vulns if v.get("cve")]


def processar_e_postar():
    init_clients()

    cves = coletar_cves()
    print(f"{len(cves)} CVEs")

    for cve in cves:
        cve_id = cve["id"]

        if cve_ja_existe(cve_id):
            continue

        analise = analisar_com_llama(cve_id, cve["summary"], cve["cvss"])
        if not analise:
            continue

        salvar_no_supabase(analise, cve_id, cve, AUTO_PUBLISH)

        if AUTO_PUBLISH:
            enviar_discord(cve_id, analise)

        print("OK:", cve_id)


if __name__ == "__main__":
    processar_e_postar()