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
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK_URL")
AUTO_PUBLISH = os.getenv("AUTO_PUBLISH", "false").strip().lower() in {"1", "true", "yes", "y"}

# NVD API
NVD_BASE = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0/")
if not NVD_BASE.endswith('/'):
    NVD_BASE += '/'
NVD_API_URL = NVD_BASE

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_URL_TEMPLATE = "https://nvd.nist.gov/vuln/detail/{cve_id}"
NVD_RESULTS_PER_PAGE = int(os.getenv("NVD_RESULTS_PER_PAGE", "20"))

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
HEADERS = {"User-Agent": "kamaz-intel-bot/2.1", "Accept": "application/json"}

supabase = None
groq_client = None

session = requests.Session()
session.headers.update(HEADERS)

if NVD_API_KEY:
    session.headers.update({"apiKey": NVD_API_KEY})

# =========================
# INIT
# =========================
def init_clients():
    global supabase, groq_client

    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("Faltam chaves do Supabase no ambiente.")

    supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

    if GROQ_API_KEY:
        groq_client = Groq(api_key=GROQ_API_KEY)

# =========================
# HELPERS
# =========================
def now_iso():
    return datetime.now(timezone.utc).isoformat()

def severity_from_cvss(cvss):
    try:
        score = float(cvss)
        if score >= 9.0: return "critical"
        if score >= 7.0: return "high"
        if score >= 4.0: return "medium"
        if score > 0: return "low"
    except:
        pass
    return "info"

def clean_json_text(raw):
    """
    Remove ```json ... ``` e lixo de formatação
    """
    if not raw:
        return ""

    raw = raw.strip()

    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?", "", raw, flags=re.IGNORECASE)
        raw = re.sub(r"```$", "", raw).strip()

    return raw

# =========================
# NVD FETCH
# =========================
def coletar_cves():
    print("📡 Coletando CVEs do NVD...")

    params = {
        "resultsPerPage": NVD_RESULTS_PER_PAGE
    }

    try:
        resp = session.get(NVD_API_URL, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"❌ Erro ao buscar CVEs: {e}")
        return []

    cves = []

    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id")

        descriptions = cve_data.get("descriptions", [])
        summary = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

        metrics = cve_data.get("metrics", {})
        cvss = None

        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        severity = severity_from_cvss(cvss)

        cves.append({
            "id": cve_id,
            "summary": summary,
            "cvss": cvss,
            "severity": severity,
            "url": NVD_URL_TEMPLATE.format(cve_id=cve_id),
            "created_at": now_iso()
        })

    print(f"✅ {len(cves)} CVEs coletadas")
    return cves

# =========================
# GROQ ANALYSIS
# =========================
def analisar_com_llama(cve):
    if not groq_client:
        return None

    prompt = f"""
Analyze this CVE and return JSON:

CVE: {cve['id']}
Summary: {cve['summary']}
CVSS: {cve['cvss']}

Return:
{{
  "impact": "...",
  "exploitability": "...",
  "recommendation": "..."
}}
"""

    try:
        response = groq_client.chat.completions.create(
            model="llama3-70b-8192",
            messages=[{"role": "user", "content": prompt}],
        )

        content = response.choices[0].message.content
        content = clean_json_text(content)

        return json.loads(content)

    except Exception as e:
        print(f"⚠️ Erro LLM {cve['id']}: {e}")
        return None

# =========================
# DATABASE
# =========================
def salvar_cve(cve):
    try:
        supabase.table("cves").insert(cve).execute()
        print(f"💾 Salvo: {cve['id']}")
    except Exception as e:
        print(f"⚠️ Erro ao salvar {cve['id']}: {e}")

# =========================
# DISCORD
# =========================
def enviar_discord(cve):
    if not DISCORD_WEBHOOK:
        return

    data = {
        "content": f"""
🚨 **{cve['id']}**
Severity: {cve['severity'].upper()}
CVSS: {cve['cvss']}

{cve['summary']}

🔗 {cve['url']}
"""
    }

    try:
        requests.post(DISCORD_WEBHOOK, json=data, timeout=10)
        print(f"📢 Enviado: {cve['id']}")
    except Exception as e:
        print(f"⚠️ Discord erro: {e}")

# =========================
# MAIN PIPELINE
# =========================
def processar_e_postar():
    init_clients()

    cves = coletar_cves()

    for cve in cves:
        if cve["severity"] not in ALLOWED_SEVERITIES:
            continue

        analysis = analisar_com_llama(cve)
        if analysis:
            cve.update(analysis)

        salvar_cve(cve)

        if AUTO_PUBLISH:
            enviar_discord(cve)

        time.sleep(1)  # evita rate limit

# =========================
# ENTRYPOINT
# =========================
if __name__ == "__main__":
    processar_e_postar()