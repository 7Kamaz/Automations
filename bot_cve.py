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
CVE_API_URL = os.getenv("CVE_API_URL", "https://cve.circl.lu/api/last/20")
NVD_URL_TEMPLATE = os.getenv("NVD_URL_TEMPLATE", "https://nvd.nist.gov/vuln/detail/{cve_id}")

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
ALLOWED_VECTOR = {"Rede", "Local", "Adjacente", "Físico", "Desconhecido"}
ALLOWED_COMPLEXITY = {"Baixa", "Média", "Alta", "Desconhecida"}
ALLOWED_AUTH = {"Nenhuma", "Usuário", "Administrador", "Desconhecida"}

HEADERS = {
    "User-Agent": "cve-news-bot/1.0"
}

supabase = None
groq_client = None
session = requests.Session()
session.headers.update(HEADERS)


def init_clients():
    global supabase, groq_client

    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("SUPABASE_URL ou SUPABASE_SERVICE_ROLE_KEY não configurados")
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY não configurada")

    supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
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
        if cvss is None or cvss == "":
            return "info"
        score = float(cvss)
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
        return "info"
    except Exception:
        return "info"


def clean_json_text(raw):
    raw = raw.strip()

    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE)
        raw = re.sub(r"\s*```$", "", raw)

    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1 and end > start:
        raw = raw[start:end + 1]

    return raw.strip()


def validar_analise(data, cve_id, cvss=None):
    if not isinstance(data, dict):
        return None

    title = normalizar_texto(data.get("title"))
    description_pt = normalizar_texto(data.get("description_pt"))
    severity = normalizar_texto(data.get("severity"), severity_from_cvss(cvss)).lower()

    tags = data.get("tags", [])
    if not isinstance(tags, list):
        tags = []
    tags = [normalizar_texto(t) for t in tags if normalizar_texto(t)]
    tags = tags[:12]

    vetor = normalizar_texto(data.get("vetor"), "Desconhecido")
    if vetor not in ALLOWED_VECTOR:
        vetor = "Desconhecido"

    complexidade = normalizar_texto(data.get("complexidade"), "Desconhecida")
    if complexidade not in ALLOWED_COMPLEXITY:
        complexidade = "Desconhecida"

    autenticacao = normalizar_texto(data.get("autenticacao"), "Desconhecida")
    if autenticacao not in ALLOWED_AUTH:
        autenticacao = "Desconhecida"

    exploit_facilidade = normalizar_texto(data.get("exploit_facilidade"), "Não confirmado")

    if not title or not description_pt:
        return None

    if severity not in ALLOWED_SEVERITIES:
        severity = severity_from_cvss(cvss)

    if len(title) > 80:
        title = title[:77].rstrip() + "..."

    return {
        "title": title,
        "description_pt": description_pt,
        "severity": severity,
        "tags": tags,
        "vetor": vetor,
        "complexidade": complexidade,
        "autenticacao": autenticacao,
        "exploit_facilidade": exploit_facilidade,
    }


def analisar_com_llama(cve_id, summary, cvss=None, max_retries=2):
    print(f"🔍 Analisando {cve_id}...")

    severity_label = severity_from_cvss(cvss)
    summary = normalizar_texto(summary, "Sem resumo disponível.")

    prompt = f"""Analise a vulnerabilidade abaixo e responda SOMENTE com um objeto JSON válido, sem texto antes ou depois, sem markdown, sem backticks.

CVE ID: {cve_id}
CVSS Score: {cvss if cvss is not None else 'N/A'}
Severidade calculada: {severity_label}
Resumo original (EN): {summary}

Responda com exatamente este schema JSON:
{{
  "title": "string — CVE ID + produto afetado + tipo de vulnerabilidade em PT-BR, máx 80 chars",
  "description_pt": "string — 2 a 4 frases em PT-BR: o que é a falha, como pode ser explorada, qual o impacto real. Tom técnico e direto. Sem emojis.",
  "severity": "uma das opções: critical, high, medium, low, info",
  "tags": ["array", "de", "strings", "ex: RCE, Windows, privilege-escalation, unauthenticated"],
  "vetor": "string — Rede | Local | Adjacente | Físico | Desconhecido",
  "complexidade": "string — Baixa | Média | Alta | Desconhecida",
  "autenticacao": "string — Nenhuma | Usuário | Administrador | Desconhecida",
  "exploit_facilidade": "string — frase curta sobre dificuldade de exploração"
}}"""

    system = (
        "Você é um analisador de CVEs especializado em segurança ofensiva. "
        "Responda sempre em português do Brasil. "
        "Responda somente com JSON válido, sem nenhum texto adicional."
    )

    last_error = None

    for attempt in range(1, max_retries + 1):
        try:
            completion = groq_client.chat.completions.create(
                model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
            )

            raw = completion.choices[0].message.content.strip()
            raw = clean_json_text(raw)
            parsed = json.loads(raw)
            validated = validar_analise(parsed, cve_id, cvss)

            if validated:
                return validated

            print(f"⚠️ Resposta inválida para {cve_id} na tentativa {attempt}")
            last_error = "validação falhou"

        except json.JSONDecodeError as e:
            print(f"❌ JSON inválido para {cve_id} na tentativa {attempt}: {e}")
            last_error = e
        except Exception as e:
            print(f"❌ Erro na análise de {cve_id} na tentativa {attempt}: {e}")
            last_error = e

        if attempt < max_retries:
            time.sleep(1.5 * attempt)

    print(f"❌ Falha final ao analisar {cve_id}: {last_error}")
    return None


def cve_ja_existe(cve_id):
    try:
        res = supabase.table("news_articles").select("id").eq("cve_id", cve_id).limit(1).execute()
        return bool(getattr(res, "data", []) or [])
    except Exception as e:
        print(f"⚠️ Falha ao verificar duplicidade de {cve_id}: {e}")
        return False


def salvar_no_supabase(analise, cve_id, cve, published=False):
    payload = {
        "title": analise["title"],
        "description_pt": analise["description_pt"],
        "severity": analise["severity"],
        "tags": analise.get("tags", []),
        "vetor": analise.get("vetor", "Desconhecido"),
        "complexidade": analise.get("complexidade", "Desconhecida"),
        "autenticacao": analise.get("autenticacao", "Desconhecida"),
        "exploit_facilidade": analise.get("exploit_facilidade", "Não confirmado"),
        "original_url": NVD_URL_TEMPLATE.format(cve_id=cve_id),
        "cve_id": cve_id,
        "published_at": cve.get("published") or now_iso(),
        "published": bool(published),
    }

    return supabase.table("news_articles").insert(payload).execute()


def enviar_discord(cve_id, analise):
    if not DISCORD_WEBHOOK:
        return

    msg_discord = (
        f"📢 NOVA CVE: {cve_id}\n"
        f"{analise['title']}\n\n"
        f"{analise['description_pt']}\n\n"
        f"Pentest View:\n"
        f"- Vetor: {analise.get('vetor')}\n"
        f"- Complexidade: {analise.get('complexidade')}\n"
        f"- Autenticação: {analise.get('autenticacao')}\n"
        f"- Exploit: {analise.get('exploit_facilidade')}\n\n"
        f"{NVD_URL_TEMPLATE.format(cve_id=cve_id)}"
    )

    try:
        resp = session.post(DISCORD_WEBHOOK, json={"content": msg_discord}, timeout=15)
        if resp.status_code >= 400:
            print(f"⚠️ Discord retornou {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        print(f"⚠️ Falha ao enviar para Discord em {cve_id}: {e}")


def coletar_cves():
    print("📡 Coletando CVEs...")
    resp = session.get(CVE_API_URL, timeout=20)
    resp.raise_for_status()

    data = resp.json()
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ("cves", "items", "results", "data"):
            if key in data and isinstance(data[key], list):
                return data[key]

    raise RuntimeError("Formato inesperado da API de CVEs")


def processar_e_postar():
    init_clients()

    cves = coletar_cves()
    print(f"📦 {len(cves)} CVEs recebidas")

    for cve in cves:
        cve_id = normalizar_texto(cve.get("id"))
        summary = cve.get("summary")
        cvss = cve.get("cvss")

        if not cve_id:
            continue

        if cve_ja_existe(cve_id):
            print(f"↩️ Já existe: {cve_id}")
            continue

        analise = analisar_com_llama(cve_id, summary, cvss)
        if not analise:
            continue

        try:
            salvar_no_supabase(analise, cve_id, cve, published=AUTO_PUBLISH)
            if AUTO_PUBLISH:
                enviar_discord(cve_id, analise)

            print(f"✅ {cve_id} salvo com sucesso (published={AUTO_PUBLISH})")

        except Exception as e:
            print(f"❌ Erro ao salvar/enviar {cve_id}: {e}")


if __name__ == "__main__":
    processar_e_postar()
