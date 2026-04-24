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

# =========================
# CONFIG
# =========================
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK_URL")

AUTO_PUBLISH = os.getenv("AUTO_PUBLISH", "false").lower() in {"1", "true", "yes"}

NVD_BASE = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0/")
if not NVD_BASE.endswith("/"):
    NVD_BASE += "/"

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_RESULTS_PER_PAGE = int(os.getenv("NVD_RESULTS_PER_PAGE", "20"))

HEADERS = {
    "User-Agent": "kamaz-intel-bot/3.0",
    "Accept": "application/json",
}

session = requests.Session()
session.headers.update(HEADERS)

if NVD_API_KEY:
    session.headers.update({"apiKey": NVD_API_KEY})

supabase = None
groq_client = None


# =========================
# INIT
# =========================
def init_clients():
    global supabase, groq_client

    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("Erro Supabase")

    if not GROQ_API_KEY:
        raise RuntimeError("Erro Groq")

    supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    groq_client = Groq(api_key=GROQ_API_KEY)


# =========================
# HELPERS
# =========================
def now_iso():
    return datetime.now(timezone.utc).isoformat()


def severity_from_cvss(cvss):
    try:
        score = float(cvss)
        if score >= 9: return "critical"
        if score >= 7: return "high"
        if score >= 4: return "medium"
        if score > 0: return "low"
    except:
        pass
    return "info"


def clean_json(raw):
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?", "", raw)
    raw = re.sub(r"```$", "", raw)

    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1:
        raw = raw[start:end+1]

    return raw


# =========================
# NVD
# =========================
def coletar_cves():
    print("📡 NVD...")

    try:
        resp = session.get(NVD_BASE, params={"resultsPerPage": NVD_RESULTS_PER_PAGE}, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print("Erro NVD:", e)
        return []

    cves = []

    for item in data.get("vulnerabilities", []):
        c = item.get("cve", {})

        cve_id = c.get("id")
        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")

        metrics = c.get("metrics", {})
        cvss = None

        for k in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if k in metrics:
                cvss = metrics[k][0]["cvssData"]["baseScore"]
                break

        cves.append({
            "id": cve_id,
            "summary": desc,
            "cvss": cvss,
            "published": c.get("published")
        })

    return cves


# =========================
# DUPLICIDADE
# =========================
def cve_exists(cve_id):
    try:
        res = supabase.table("news_articles").select("id").eq("cve_id", cve_id).limit(1).execute()
        return bool(res.data)
    except:
        return False


# =========================
# LLM
# =========================
def analisar(cve_id, summary, cvss):
    print("🔍", cve_id)

    prompt = f"""
CVE: {cve_id}
CVSS: {cvss}
Summary: {summary}

Return JSON:
{{
"title":"",
"description_pt":"",
"severity":"",
"tags":[],
"vetor":"",
"complexidade":"",
"autenticacao":"",
"exploit_facilidade":""
}}
"""

    try:
        r = groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1
        )

        raw = clean_json(r.choices[0].message.content)
        return json.loads(raw)

    except Exception as e:
        print("Erro LLM:", e)
        return None


# =========================
# SAVE
# =========================
def salvar(cve_id, cve, analise):
    payload = {
        "title": analise["title"],
        "description_pt": analise["description_pt"],
        "severity": analise["severity"],
        "tags": analise.get("tags", []),
        "vetor": analise.get("vetor"),
        "complexidade": analise.get("complexidade"),
        "autenticacao": analise.get("autenticacao"),
        "exploit_facilidade": analise.get("exploit_facilidade"),
        "original_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "cve_id": cve_id,
        "published_at": cve.get("published") or now_iso(),
        "published": AUTO_PUBLISH,
    }

    supabase.table("news_articles").insert(payload).execute()


# =========================
# DISCORD
# =========================
def discord(cve_id, analise):
    if not DISCORD_WEBHOOK:
        return

    msg = f"""🚨 {cve_id}

{analise['title']}

{analise['description_pt']}

🔗 https://nvd.nist.gov/vuln/detail/{cve_id}
"""

    requests.post(DISCORD_WEBHOOK, json={"content": msg})


# =========================
# MAIN
# =========================
def run():
    init_clients()

    cves = coletar_cves()

    for cve in cves:
        cve_id = cve.get("id")

        if not cve_id or cve_exists(cve_id):
            continue

        analise = analisar(cve_id, cve["summary"], cve["cvss"])
        if not analise:
            continue

        try:
            salvar(cve_id, cve, analise)

            if AUTO_PUBLISH:
                discord(cve_id, analise)

            print("✅", cve_id)

        except Exception as e:
            print("Erro salvar:", e)

        time.sleep(1.2)


if __name__ == "__main__":
    run()