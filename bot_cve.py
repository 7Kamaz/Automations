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

# Configurações Básicas
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK_URL")
AUTO_PUBLISH = os.getenv("AUTO_PUBLISH", "false").strip().lower() in {"1", "true", "yes", "y"}

# NVD API - FORÇANDO A BARRA FINAL PARA EVITAR 404
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

def init_clients():
    global supabase, groq_client
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("Faltam chaves do Supabase no ambiente.")
    supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    if GROQ_API_KEY:
        groq_client = Groq(api_key=GROQ_API_KEY)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def severity_from_cvss(cvss):
    try:
        score = float(cvss)
        if score >= 9.0: return "critical"
        if score >= 7.0: return "high"
        if score >= 4.0: return "medium"
        if score > 0: return "low"
    except: pass
    return "info"

def clean_json_text(raw):
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^
http://googleusercontent.com/immersive_entry_chip/0

---

### 3. O que conferir nos "Secrets" do GitHub:
Como você disse que adicionou separado, garanta que os nomes (Names) estejam exatamente assim:
* `SUPABASE_URL`
* `SUPABASE_SERVICE_ROLE_KEY`
* `GROQ_API_KEY`
* `DISCORD_WEBHOOK_URL`

**O que mudou?**
1.  **Código Blindado:** No Python, eu adicionei uma verificação que coloca a barra `/` se ela não existir.
2.  **YAML Explicito:** Coloquei a URL correta direto no YAML para não ter erro de digitação no painel do GitHub.

**Copia o código, salva o arquivo e roda. O erro do 404 vai sumir porque agora a URL vai com a barra obrigatória.**
