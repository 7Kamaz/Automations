""" 
bot_cve.py — Kamaz Intel Bot v4.3
Fonte: NVD API v2.0
Pipeline: NVD → Groq (llama-3.3-70b-versatile) → Supabase (news_articles) → Discord
GitHub Actions: roda a cada hora via cron "0 * * * *"
"""

import json
import os
import re
import time
from datetime import datetime, timezone, timedelta

import requests
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

# =========================
# CONFIG — todos os secrets
# =========================
SUPABASE_URL              = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
GROQ_API_KEY              = os.getenv("GROQ_API_KEY")
GROQ_MODEL                = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
DISCORD_WEBHOOK           = os.getenv("DISCORD_WEBHOOK_URL")
AUTO_PUBLISH              = os.getenv("AUTO_PUBLISH", "false").strip().lower() in {"1", "true", "yes", "y"}

# NVD
_nvd_base          = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0/")
NVD_API_URL        = _nvd_base if _nvd_base.endswith("/") else _nvd_base + "/"
NVD_API_KEY        = os.getenv("NVD_API_KEY")          # opcional mas aumenta rate limit
NVD_RESULTS_PER_PAGE = int(os.getenv("NVD_RESULTS_PER_PAGE", "20"))
NVD_LOOKBACK_MINUTES = int(os.getenv("NVD_LOOKBACK_MINUTES", "65"))
NVD_URL_TEMPLATE   = "https://nvd.nist.gov/vuln/detail/{cve_id}"

GROQ_TIMEOUT = float(os.getenv("GROQ_TIMEOUT", "60"))
GROQ_MAX_RETRIES = int(os.getenv("GROQ_MAX_RETRIES", "3"))

# Conjuntos de validação para payload da IA
ALLOWED_SEVERITIES  = {"critical", "high", "medium", "low", "info"}
ALLOWED_VECTOR      = {"Rede", "Local", "Adjacente", "Físico", "Desconhecido"}
ALLOWED_COMPLEXITY  = {"Baixa", "Média", "Alta", "Desconhecida"}
ALLOWED_AUTH        = {"Nenhuma", "Usuário", "Administrador", "Desconhecida"}

HEADERS = {"User-Agent": "kamaz-intel-bot/4.3", "Accept": "application/json"}

# Estado global
supabase = None
session  = requests.Session()
session.headers.update(HEADERS)
if NVD_API_KEY:
    session.headers.update({"apiKey": NVD_API_KEY})


# =========================
# INICIALIZAÇÃO
# =========================
def init_clients():
    global supabase

    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("SUPABASE_URL ou SUPABASE_SERVICE_ROLE_KEY não configurados")
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY não configurada")

    supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    print("✅ Clientes inicializados")


# =========================
# HELPERS
# =========================
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def normalizar_texto(valor, padrao: str = "") -> str:
    if valor is None:
        return padrao
    if isinstance(valor, str):
        return valor.strip()
    return str(valor).strip()


def severity_from_cvss(cvss) -> str:
    try:
        if cvss is None or cvss == "":
            return "info"
        score = float(cvss)
        if score >= 9.0: return "critical"
        if score >= 7.0: return "high"
        if score >= 4.0: return "medium"
        if score > 0:    return "low"
    except Exception:
        pass
    return "info"


def clean_json_text(raw: str) -> str:
    """Remove blocos markdown e isola o objeto JSON."""
    if not raw:
        return ""
    raw = raw.strip()
    if "```" in raw:
        raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE | re.MULTILINE)
        raw = re.sub(r"\s*```$", "", raw, flags=re.MULTILINE)
        raw = raw.strip()
    start = raw.find("{")
    end   = raw.rfind("}")
    if start != -1 and end != -1 and end > start:
        raw = raw[start:end + 1]
    return raw.strip()


# =========================
# NVD — COLETA
# =========================
def coletar_cves() -> list:
    print("📡 Coletando CVEs do NVD...")

    agora  = datetime.now(timezone.utc)
    inicio = agora - timedelta(minutes=NVD_LOOKBACK_MINUTES)

    params_base = {
        "lastModStartDate": iso_z(inicio),
        "lastModEndDate":   iso_z(agora),
        "resultsPerPage":   NVD_RESULTS_PER_PAGE,
        "startIndex":       0,
    }

    cves         = []
    total_results = None
    start_index  = 0

    while True:
        params = dict(params_base)
        params["startIndex"] = start_index

        try:
            resp = session.get(NVD_API_URL, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            print(f"❌ Erro ao buscar CVEs do NVD: {e}")
            return []

        if total_results is None:
            total_results = data.get("totalResults", 0)
            print(f"📊 totalResults={total_results} | janela={NVD_LOOKBACK_MINUTES} min")

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        for item in vulnerabilities:
            cve_data = item.get("cve", {})
            cve_id   = cve_data.get("id")
            if not cve_id:
                continue

            summary = next(
                (d.get("value", "") for d in cve_data.get("descriptions", []) if d.get("lang") == "en"),
                ""
            )

            metrics = cve_data.get("metrics", {})
            cvss    = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    try:
                        cvss = metrics[key][0]["cvssData"]["baseScore"]
                        break
                    except (KeyError, IndexError, TypeError):
                        continue

            published = cve_data.get("published", "")
            # Ignora CVEs antigas — só aceita publicadas nos últimos 30 dias
            try:
                if published:
                    pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
                    if pub_dt < agora - timedelta(days=30):
                        print(f"⏭️  Ignorando {cve_id} (publicada em {published[:10]})")
                        continue
            except Exception:
                pass

            cves.append({
                "id":        cve_id,
                "summary":   summary,
                "cvss":      cvss,
                "published": published,
            })

        start_index += len(vulnerabilities)
        if total_results is not None and start_index >= total_results:
            break

        time.sleep(0.7)

    print(f"📦 {len(cves)} CVEs recebidas")
    return cves


# =========================
# DEDUPLICAÇÃO
# =========================
def cve_ja_existe(cve_id: str) -> bool:
    try:
        res = supabase.table("news_articles").select("id").eq("cve_id", cve_id).limit(1).execute()
        return bool(getattr(res, "data", None))
    except Exception as e:
        print(f"⚠️  Falha ao verificar duplicidade de {cve_id}: {e}")
        return False


# =========================
# VALIDAÇÃO DO PAYLOAD DA IA
# =========================
def validar_analise(data: dict, cve_id: str, cvss=None) -> dict | None:
    if not isinstance(data, dict):
        return None

    title          = normalizar_texto(data.get("title"))
    description_pt = normalizar_texto(data.get("description_pt"))
    severity       = normalizar_texto(data.get("severity"), severity_from_cvss(cvss)).lower()

    if not title or not description_pt:
        return None

    tags = data.get("tags", [])
    if not isinstance(tags, list):
        tags = []
    tags = [normalizar_texto(t) for t in tags if normalizar_texto(t)][:12]

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

    if severity not in ALLOWED_SEVERITIES:
        severity = severity_from_cvss(cvss)

    if len(title) > 80:
        title = title[:77].rstrip() + "..."

    return {
        "title":              title,
        "description_pt":     description_pt,
        "severity":           severity,
        "tags":               tags,
        "vetor":              vetor,
        "complexidade":       complexidade,
        "autenticacao":       autenticacao,
        "exploit_facilidade": exploit_facilidade,
    }


# =========================
# ANÁLISE VIA GROQ (requests direto — sem SDK)
# =========================
def analisar_com_llama(cve_id: str, summary: str, cvss=None) -> dict | None:
    print(f"🔍 Analisando {cve_id}...")

    severity_label = severity_from_cvss(cvss)
    summary        = normalizar_texto(summary, "Sem resumo disponível.")

    system = (
        "Você é um analisador de CVEs especializado em segurança ofensiva e pentesting. "
        "Responda sempre em português do Brasil. "
        "Responda somente com JSON válido, sem nenhum texto adicional, sem markdown."
    )

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

    last_error = None
    for attempt in range(1, GROQ_MAX_RETRIES + 1):
        try:
            resp = session.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type":  "application/json",
                },
                json={
                    "model":       GROQ_MODEL,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user",   "content": prompt},
                    ],
                    "temperature": 0.1,
                    "max_tokens":  500,
                },
                timeout=GROQ_TIMEOUT,
            )
            resp.raise_for_status()

            raw       = resp.json()["choices"][0]["message"]["content"].strip()
            raw       = clean_json_text(raw)
            parsed    = json.loads(raw)
            validated = validar_analise(parsed, cve_id, cvss)

            if validated:
                return validated

            print(f"⚠️  Resposta inválida para {cve_id} na tentativa {attempt}")
            last_error = "validação falhou"

        except json.JSONDecodeError as e:
            print(f"❌ JSON inválido para {cve_id} na tentativa {attempt}: {e}")
            last_error = e
        except Exception as e:
            print(f"❌ Erro na análise de {cve_id} na tentativa {attempt}: {e}")
            last_error = e

        if attempt < GROQ_MAX_RETRIES:
            time.sleep(1.5 * attempt)

    print(f"❌ Falha final ao analisar {cve_id}: {last_error}")
    return None


# =========================
# SUPABASE — SAVE
# =========================
def salvar_no_supabase(analise: dict, cve_id: str, cve: dict) -> None:
    payload = {
        "cve_id":             cve_id,
        "title":              analise.get("title"),
        "description_pt":     analise.get("description_pt"),
        "severity":           analise.get("severity"),
        "tags":               analise.get("tags", []),
        "vetor":              analise.get("vetor", "Desconhecido"),
        "complexidade":       analise.get("complexidade", "Desconhecida"),
        "autenticacao":       analise.get("autenticacao", "Desconhecida"),
        "exploit_facilidade": analise.get("exploit_facilidade", "Não confirmado"),
        "cvss":               cve.get("cvss"),
        "published":          cve.get("published"),
        "source":             "NVD",
        "source_url":         NVD_URL_TEMPLATE.format(cve_id=cve_id),
        "created_at":         now_iso(),
        "updated_at":         now_iso(),
    }

    try:
        res = supabase.table("news_articles").insert(payload).execute()
        if getattr(res, "error", None):
            raise RuntimeError(str(res.error))
    except Exception as e:
        print(f"❌ Falha ao inserir {cve_id} no Supabase: {e}")
        raise


# =========================
# DISCORD — NOTIFY
# =========================
def enviar_discord(cve_id: str, analise: dict) -> None:
    if not DISCORD_WEBHOOK:
        return

    severity_emoji = {
        "critical": "🔴",
        "high":     "🟠",
        "medium":   "🟡",
        "low":      "🟢",
        "info":     "⚪",
    }.get(analise["severity"], "⚫")

    msg = (
        f"🚨 **NOVA CVE: {cve_id}** {severity_emoji}\n"
        f"**{analise['title']}**\n\n"
        f"{analise['description_pt']}\n\n"
        f"**Análise Pentest:**\n"
        f"• Vetor: {analise.get('vetor', 'Desconhecido')}\n"
        f"• Complexidade: {analise.get('complexidade', 'Desconhecida')}\n"
        f"• Autenticação: {analise.get('autenticacao', 'Desconhecida')}\n"
        f"• Exploit: {analise.get('exploit_facilidade', 'Não confirmado')}\n\n"
        f"🔗 {NVD_URL_TEMPLATE.format(cve_id=cve_id)}"
    )

    try:
        resp = session.post(DISCORD_WEBHOOK, json={"content": msg}, timeout=15)
        if resp.status_code >= 400:
            print(f"⚠️  Discord retornou {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        print(f"⚠️  Falha ao enviar Discord para {cve_id}: {e}")


# =========================
# PIPELINE PRINCIPAL
# =========================
def processar_e_postar() -> None:
    init_clients()

    cves = coletar_cves()
    if not cves:
        print("ℹ️  Nenhuma CVE nova publicada na janela. Encerrando.")
        return

    processadas = 0
    for cve in cves:
        cve_id = normalizar_texto(cve.get("id"))
        if not cve_id:
            continue

        if cve_ja_existe(cve_id):
            print(f"↩️  Já existe: {cve_id}")
            continue

        analise = analisar_com_llama(cve_id, cve.get("summary"), cve.get("cvss"))
        if not analise:
            continue

        try:
            salvar_no_supabase(analise, cve_id, cve)
            if AUTO_PUBLISH:
                enviar_discord(cve_id, analise)
            print(f"✅ {cve_id} salvo (auto_publish={AUTO_PUBLISH})")
            processadas += 1
        except Exception as e:
            print(f"❌ Erro ao salvar/enviar {cve_id}: {e}")

        time.sleep(1.2)

    print(f"\n🏁 Pipeline concluído. {processadas}/{len(cves)} CVEs processadas.")


# =========================
# ENTRYPOINT
# =========================
if __name__ == "__main__":
    processar_e_postar()
