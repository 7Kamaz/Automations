"""
bot_cve.py — Kamaz Intel Bot v4.0
Fonte: NVD API v2.0
Pipeline: NVD → Groq (llama-3.3-70b-versatile) → Supabase (news_articles) → Discord
GitHub Actions: roda a cada hora via cron "0 * * * *"
"""

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
NVD_URL_TEMPLATE   = "https://nvd.nist.gov/vuln/detail/{cve_id}"

# Conjuntos de validação para payload da IA
ALLOWED_SEVERITIES  = {"critical", "high", "medium", "low", "info"}
ALLOWED_VECTOR      = {"Rede", "Local", "Adjacente", "Físico", "Desconhecido"}
ALLOWED_COMPLEXITY  = {"Baixa", "Média", "Alta", "Desconhecida"}
ALLOWED_AUTH        = {"Nenhuma", "Usuário", "Administrador", "Desconhecida"}

HEADERS = {"User-Agent": "kamaz-intel-bot/4.0", "Accept": "application/json"}

# Estado global
supabase    = None
groq_client = None
session     = requests.Session()
session.headers.update(HEADERS)
if NVD_API_KEY:
    session.headers.update({"apiKey": NVD_API_KEY})


# =========================
# INICIALIZAÇÃO
# =========================
def init_clients():
    global supabase, groq_client

    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("SUPABASE_URL ou SUPABASE_SERVICE_ROLE_KEY não configurados")
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY não configurada")

    supabase    = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    groq_client = Groq(api_key=GROQ_API_KEY)
    print("✅ Clientes inicializados")


# =========================
# HELPERS
# =========================
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    # Remove cercas ```json ... ``` ou ``` ... ```
    if "```" in raw:
        raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE | re.MULTILINE)
        raw = re.sub(r"\s*```$", "", raw, flags=re.MULTILINE)
        raw = raw.strip()
    # Isola {…} caso a IA adicione texto antes/depois
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
    params = {"resultsPerPage": NVD_RESULTS_PER_PAGE}

    try:
        resp = session.get(NVD_API_URL, params=params, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"❌ Erro ao buscar CVEs do NVD: {e}")
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id   = cve_data.get("id")
        if not cve_id:
            continue

        # Descrição em inglês
        summary = next(
            (d["value"] for d in cve_data.get("descriptions", []) if d["lang"] == "en"),
            ""
        )

        # CVSS — tenta v3.1, v3.0, v2 em ordem
        metrics = cve_data.get("metrics", {})
        cvss    = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                try:
                    cvss = metrics[key][0]["cvssData"]["baseScore"]
                    break
                except (KeyError, IndexError):
                    continue

        cves.append({
            "id":        cve_id,
            "summary":   summary,
            "cvss":      cvss,
            "published": cve_data.get("published"),
        })

    print(f"📦 {len(cves)} CVEs recebidas")
    return cves


# =========================
# DEDUPLICAÇÃO
# =========================
def cve_ja_existe(cve_id: str) -> bool:
    """Consulta Supabase ANTES de chamar a IA para evitar gasto de cota."""
    try:
        res = supabase.table("news_articles").select("id").eq("cve_id", cve_id).limit(1).execute()
        return bool(getattr(res, "data", None))
    except Exception as e:
        print(f"⚠️  Falha ao verificar duplicidade de {cve_id}: {e}")
        return False  # Em caso de erro, tenta processar mesmo assim


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

    # Tags: lista de strings, máx 12
    tags = data.get("tags", [])
    if not isinstance(tags, list):
        tags = []
    tags = [normalizar_texto(t) for t in tags if normalizar_texto(t)][:12]

    # Campos pentest com fallback para valor padrão se fora do allowed set
    vetor          = normalizar_texto(data.get("vetor"), "Desconhecido")
    if vetor not in ALLOWED_VECTOR:
        vetor = "Desconhecido"

    complexidade   = normalizar_texto(data.get("complexidade"), "Desconhecida")
    if complexidade not in ALLOWED_COMPLEXITY:
        complexidade = "Desconhecida"

    autenticacao   = normalizar_texto(data.get("autenticacao"), "Desconhecida")
    if autenticacao not in ALLOWED_AUTH:
        autenticacao = "Desconhecida"

    exploit_facilidade = normalizar_texto(data.get("exploit_facilidade"), "Não confirmado")

    # Severity fallback
    if severity not in ALLOWED_SEVERITIES:
        severity = severity_from_cvss(cvss)

    # Trunca title se necessário
    if len(title) > 80:
        title = title[:77].rstrip() + "..."

    return {
        "title":             title,
        "description_pt":    description_pt,
        "severity":          severity,
        "tags":              tags,
        "vetor":             vetor,
        "complexidade":      complexidade,
        "autenticacao":      autenticacao,
        "exploit_facilidade": exploit_facilidade,
    }


# =========================
# ANÁLISE VIA GROQ (LLAMA)
# =========================
def analisar_com_llama(cve_id: str, summary: str, cvss=None, max_retries: int = 2) -> dict | None:
    print(f"🔍 Analisando {cve_id}...")

    severity_label = severity_from_cvss(cvss)
    summary        = normalizar_texto(summary, "Sem resumo disponível.")

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
        "Você é um analisador de CVEs especializado em segurança ofensiva e pentesting. "
        "Responda sempre em português do Brasil. "
        "Responda somente com JSON válido, sem nenhum texto adicional, sem markdown."
    )

    last_error = None
    for attempt in range(1, max_retries + 1):
        try:
            completion = groq_client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user",   "content": prompt},
                ],
                temperature=0.1,
            )

            raw       = completion.choices[0].message.content.strip()
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

        if attempt < max_retries:
            time.sleep(1.5 * attempt)   # backoff progressivo

    print(f"❌ Falha final ao analisar {cve_id}: {last_error}")
    return None


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
        print("Nenhuma CVE recebida. Encerrando.")
        return

    processadas = 0
    for cve in cves:
        cve_id = normalizar_texto(cve.get("id"))
        if not cve_id:
            continue

        # Deduplicação ANTES da IA (evita gasto de cota)
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
            print(f"✅ {cve_id} salvo (published={AUTO_PUBLISH})")
            processadas += 1
        except Exception as e:
            print(f"❌ Erro ao salvar/enviar {cve_id}: {e}")

        time.sleep(1.2)   # respeita rate limit do NVD (sem key: 5 req/30s)

    print(f"\n🏁 Pipeline concluído. {processadas}/{len(cves)} CVEs processadas.")


# =========================
# ENTRYPOINT
# =========================
if __name__ == "__main__":
    processar_e_postar()
