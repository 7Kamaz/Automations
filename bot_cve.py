"""
bot_cve.py — Kamaz Intel Bot v4.1 (fix syntax)
"""

import json
import os
import re
import time
from datetime import datetime, timezone, timedelta

import requests
from dotenv import load_dotenv
from groq import Groq
from supabase import create_client

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK_URL")
AUTO_PUBLISH = os.getenv("AUTO_PUBLISH", "false").strip().lower() in {"1", "true", "yes", "y"}

_nvd_base = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0/")
NVD_API_URL = _nvd_base if _nvd_base.endswith("/") else _nvd_base + "/"
NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_RESULTS_PER_PAGE = int(os.getenv("NVD_RESULTS_PER_PAGE", "2000"))
NVD_LOOKBACK_MINUTES = int(os.getenv("NVD_LOOKBACK_MINUTES", "65"))
NVD_URL_TEMPLATE = "https://nvd.nist.gov/vuln/detail/{cve_id}"

GROQ_TIMEOUT = float(os.getenv("GROQ_TIMEOUT", "30"))
GROQ_MAX_RETRIES = int(os.getenv("GROQ_MAX_RETRIES", "5"))

HEADERS = {"User-Agent": "kamaz-intel-bot/4.1", "Accept": "application/json"}

supabase = None
groq_client = None
session = requests.Session()
session.headers.update(HEADERS)
if NVD_API_KEY:
    session.headers.update({"apiKey": NVD_API_KEY})


def init_clients():
    global supabase, groq_client

    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("SUPABASE não configurado")
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY não configurada")

    supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    groq_client = Groq(api_key=GROQ_API_KEY)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def iso_z(dt):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def coletar_cves():
    agora = datetime.now(timezone.utc)
    inicio = agora - timedelta(minutes=NVD_LOOKBACK_MINUTES)

    params = {
        "lastModStartDate": iso_z(inicio),
        "lastModEndDate": iso_z(agora),
        "resultsPerPage": NVD_RESULTS_PER_PAGE,
        "startIndex": 0
    }

    try:
        resp = session.get(NVD_API_URL, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print("Erro NVD:", e)
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id")
        if not cve_id:
            continue

        summary = ""
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                summary = d.get("value", "")

        cves.append({
            "id": cve_id,
            "summary": summary,
            "cvss": None,
            "published": cve_data.get("published")
        })

    return cves


def cve_ja_existe(cve_id):
    try:
        res = supabase.table("news_articles").select("id").eq("cve_id", cve_id).limit(1).execute()
        return bool(res.data)
    except:
        return False


def analisar_com_llama(cve_id, summary):
    for attempt in range(GROQ_MAX_RETRIES):
        try:
            completion = groq_client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[{"role": "user", "content": summary}],
                temperature=0.1
            )
            return {"title": cve_id, "description_pt": summary, "severity": "low"}
        except Exception as e:
            print("Erro Groq:", e)
            time.sleep(2 ** attempt)

    return None


def salvar_no_supabase(analise, cve_id):
    payload = {
        "cve_id": cve_id,
        "title": analise["title"],
        "description_pt": analise["description_pt"],
        "severity": analise["severity"],
        "created_at": now_iso()
    }

    supabase.table("news_articles").insert(payload).execute()


def enviar_discord(cve_id, analise):
    if not DISCORD_WEBHOOK:
        return

    msg = f"CVE: {cve_id}\n{analise['title']}"
    session.post(DISCORD_WEBHOOK, json={"content": msg})


def processar_e_postar():
    init_clients()
    cves = coletar_cves()

    for cve in cves:
        cve_id = cve.get("id")

        if cve_ja_existe(cve_id):
            continue

        analise = analisar_com_llama(cve_id, cve.get("summary"))
        if not analise:
            continue

        salvar_no_supabase(analise, cve_id)

        if AUTO_PUBLISH:
            enviar_discord(cve_id, analise)


if __name__ == "__main__":
    processar_e_postar()
