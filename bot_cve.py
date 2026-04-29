"""
bot_cve.py — Kamaz Intel Bot v5.0
Fontes: NVD API v2.0 + CIRCL CVE API + OSV.dev + GitHub Search
Pipeline:
  1. NVD        → coleta CVEs publicadas HOJE (pubStartDate/pubEndDate), CVSS >= 7.0
  2. CIRCL/OSV  → enriquece CVEs sem CVSS da NVD
  3. pending_cves → reprocessa fila de CVEs aguardando CVSS
  4. GitHub     → busca PoC/exploits públicos
  5. Groq       → análise completa em PT-BR com todos os dados enriquecidos
  6. Supabase   → persiste em news_articles
  7. Discord    → notifica via webhook

Changelog v5.0:
- Filtra SOMENTE por pubStartDate/pubEndDate — zero CVEs antigas ou modificadas
- CVSS mínimo 7.0 (High + Critical)
- Hierarquia CVSS: NVD → CIRCL → OSV
- CVEs sem CVSS entram em pending_cves, reprocessadas na próxima hora
- Busca PoC no GitHub (TOKEN_GITHUB) e CIRCL/ExploitDB
- Groq recebe todos os dados enriquecidos de uma vez antes de analisar
- Service role bypassa RLS; frontend autenticado tem apenas SELECT
"""

import json
import os
import re
import time
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

# =============================================================================
# CONFIG
# =============================================================================
SUPABASE_URL              = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
GROQ_API_KEY              = os.getenv("GROQ_API_KEY")
GROQ_MODEL                = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
DISCORD_WEBHOOK           = os.getenv("DISCORD_WEBHOOK_URL")
AUTO_PUBLISH              = os.getenv("AUTO_PUBLISH", "false").strip().lower() in {"1", "true", "yes", "y"}

NVD_BASE_URL         = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0/")
NVD_API_URL          = NVD_BASE_URL if NVD_BASE_URL.endswith("/") else NVD_BASE_URL + "/"
NVD_API_KEY          = os.getenv("NVD_API_KEY")
NVD_RESULTS_PER_PAGE = int(os.getenv("NVD_RESULTS_PER_PAGE", "2000"))
NVD_URL_TEMPLATE     = "https://nvd.nist.gov/vuln/detail/{cve_id}"

GITHUB_TOKEN         = os.getenv("TOKEN_GITHUB")  # secret TOKEN_GITHUB no Actions

CVSS_MINIMO          = float(os.getenv("CVSS_MINIMO", "7.0"))
GROQ_TIMEOUT         = float(os.getenv("GROQ_TIMEOUT", "60"))
GROQ_MAX_RETRIES     = int(os.getenv("GROQ_MAX_RETRIES", "3"))
PENDING_MAX_ATTEMPTS = int(os.getenv("PENDING_MAX_ATTEMPTS", "24"))

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}
ALLOWED_VECTOR     = {"Rede", "Local", "Adjacente", "Físico", "Desconhecido"}
ALLOWED_COMPLEXITY = {"Baixa", "Média", "Alta", "Desconhecida"}
ALLOWED_AUTH       = {"Nenhuma", "Usuário", "Administrador", "Desconhecida"}

HEADERS = {"User-Agent": "kamaz-intel-bot/5.0", "Accept": "application/json"}

supabase = None
session  = requests.Session()
session.headers.update(HEADERS)


# =============================================================================
# INICIALIZAÇÃO
# =============================================================================
def init_clients() -> None:
    global supabase
    missing = []
    if not SUPABASE_URL:              missing.append("SUPABASE_URL")
    if not SUPABASE_SERVICE_ROLE_KEY: missing.append("SUPABASE_SERVICE_ROLE_KEY")
    if not GROQ_API_KEY:              missing.append("GROQ_API_KEY")
    if not DISCORD_WEBHOOK:           missing.append("DISCORD_WEBHOOK_URL")
    if not NVD_API_KEY:               missing.append("NVD_API_KEY")
    if not GITHUB_TOKEN:              missing.append("TOKEN_GITHUB")
    if missing:
        raise RuntimeError(f"Secrets obrigatórias ausentes: {', '.join(missing)}")

    if NVD_API_KEY:
        session.headers.update({"apiKey": NVD_API_KEY})

    supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    print("✅ Clientes inicializados")


# =============================================================================
# HELPERS
# =============================================================================
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def fmt_nvd_date(dt: datetime) -> str:
    """Formato exigido pela NVD API: 2024-01-01T00:00:00.000"""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def normalizar_texto(valor, padrao: str = "") -> str:
    if valor is None:
        return padrao
    return str(valor).strip() if not isinstance(valor, str) else valor.strip()


def severity_from_cvss(cvss) -> str:
    try:
        score = float(cvss)
        if score >= 9.0: return "critical"
        if score >= 7.0: return "high"
        if score >= 4.0: return "medium"
        if score > 0:    return "low"
    except Exception:
        pass
    return "unknown"


def clean_json_text(raw: str) -> str:
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


def extrair_cvss_nvd(metrics: dict):
    """Extrai CVSS da resposta bruta da NVD — tenta V31, V30, V2."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            try:
                return float(metrics[key][0]["cvssData"]["baseScore"])
            except (KeyError, IndexError, TypeError, ValueError):
                continue
    return None


# =============================================================================
# NVD — COLETA (pubStartDate/pubEndDate — somente novas de hoje)
# =============================================================================
def coletar_cves_nvd() -> list:
    agora       = datetime.now(timezone.utc)
    hoje_inicio = agora.replace(hour=0, minute=0, second=0, microsecond=0)

    print(f"\n📡 Coletando CVEs do NVD — publicadas hoje ({hoje_inicio.strftime('%d/%m/%Y')}) ...")

    params = {
        "pubStartDate":   fmt_nvd_date(hoje_inicio),
        "pubEndDate":     fmt_nvd_date(agora),
        "resultsPerPage": NVD_RESULTS_PER_PAGE,
        "startIndex":     0,
    }

    try:
        resp = session.get(NVD_API_URL, params=params, timeout=60)
        if resp.status_code == 429:
            print("⚠️  Rate limit NVD (429). Aguardando 60s...")
            time.sleep(60)
            resp = session.get(NVD_API_URL, params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"❌ Erro ao buscar NVD: {e}")
        return []

    vulnerabilities = data.get("vulnerabilities", [])
    print(f"📊 NVD retornou {data.get('totalResults', 0)} CVEs publicadas hoje")

    # Ordena da mais antiga para mais recente
    vulnerabilities.sort(key=lambda x: x.get("cve", {}).get("published", ""))

    cves = []
    for item in vulnerabilities:
        cve_data = item.get("cve", {})
        cve_id   = cve_data.get("id")
        if not cve_id:
            continue

        published_raw = cve_data.get("published", "")
        try:
            pub_dt = datetime.fromisoformat(published_raw.replace("Z", "+00:00"))
        except Exception:
            print(f"⏭️  {cve_id} ignorada (data inválida: '{published_raw}')")
            continue

        summary = next(
            (d.get("value", "") for d in cve_data.get("descriptions", []) if d.get("lang") == "en"),
            ""
        )

        references = [
            r.get("url", "") for r in cve_data.get("references", []) if r.get("url")
        ]

        cvss = extrair_cvss_nvd(cve_data.get("metrics", {}))

        cves.append({
            "id":            cve_id,
            "summary":       summary,
            "cvss":          cvss,
            "cvss_fonte":    "NVD" if cvss is not None else None,
            "published_iso": pub_dt.isoformat(),
            "references":    references,
        })

    print(f"📦 {len(cves)} CVEs de hoje coletadas da NVD")
    return cves


# =============================================================================
# ENRIQUECIMENTO DE CVSS — CIRCL → OSV
# =============================================================================
def buscar_cvss_circl(cve_id: str):
    try:
        resp = session.get(f"https://cve.circl.lu/api/cve/{cve_id}", timeout=15)
        if resp.status_code != 200:
            return None
        data = resp.json()
        if not data:
            return None
        for field in ("cvss3", "cvss"):
            val = data.get(field)
            if val is not None:
                return float(val)
    except Exception:
        pass
    return None


def buscar_cvss_osv(cve_id: str):
    try:
        resp = session.post(
            "https://api.osv.dev/v1/query",
            json={"id": cve_id},
            timeout=15,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        for vuln in data.get("vulns", []):
            for severity in vuln.get("severity", []):
                if severity.get("type") == "CVSS_V3":
                    try:
                        return float(severity.get("score", ""))
                    except (ValueError, TypeError):
                        pass
    except Exception:
        pass
    return None


def enriquecer_cvss(cve: dict) -> dict:
    """Tenta obter CVSS de fontes alternativas se NVD não forneceu."""
    if cve.get("cvss") is not None:
        return cve

    cve_id = cve["id"]
    print(f"   🔎 {cve_id} sem CVSS na NVD — consultando CIRCL...")

    cvss = buscar_cvss_circl(cve_id)
    if cvss is not None:
        print(f"   ✅ CIRCL: CVSS={cvss}")
        cve["cvss"]       = cvss
        cve["cvss_fonte"] = "CIRCL"
        return cve

    print(f"   🔎 CIRCL vazio — consultando OSV...")
    cvss = buscar_cvss_osv(cve_id)
    if cvss is not None:
        print(f"   ✅ OSV: CVSS={cvss}")
        cve["cvss"]       = cvss
        cve["cvss_fonte"] = "OSV"
        return cve

    print(f"   ⏳ {cve_id} sem CVSS em nenhuma fonte → fila pending")
    cve["cvss_fonte"] = None
    return cve


# =============================================================================
# BUSCA DE POC / EXPLOIT
# =============================================================================
def buscar_poc_github(cve_id: str):
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    try:
        resp = requests.get(
            "https://api.github.com/search/repositories",
            params={"q": f"{cve_id} poc exploit", "sort": "updated", "per_page": 3},
            headers=headers,
            timeout=15,
        )
        if resp.status_code == 403:
            print(f"   ⚠️  GitHub rate limit para {cve_id}")
            return None
        if resp.status_code != 200:
            return None

        items = resp.json().get("items", [])
        if not items:
            return None

        best = items[0]
        return {
            "url":    best.get("html_url"),
            "title":  best.get("full_name"),
            "stars":  best.get("stargazers_count", 0),
            "source": "github",
        }
    except Exception as e:
        print(f"   ⚠️  Erro GitHub PoC {cve_id}: {e}")
        return None


def buscar_poc_circl(cve_id: str):
    try:
        resp = session.get(f"https://cve.circl.lu/api/cve/{cve_id}", timeout=15)
        if resp.status_code != 200:
            return None
        data = resp.json()
        if not data:
            return None
        ref_map      = data.get("refMap", {})
        exploit_refs = ref_map.get("EXPLOIT", [])
        if exploit_refs:
            return {
                "url":    exploit_refs[0],
                "title":  f"ExploitDB via CIRCL — {cve_id}",
                "stars":  None,
                "source": "exploitdb",
            }
    except Exception:
        pass
    return None


def buscar_poc(cve_id: str):
    """GitHub primeiro, depois CIRCL/ExploitDB."""
    poc = buscar_poc_github(cve_id)
    if poc:
        print(f"   💣 PoC GitHub: {poc['url']}")
        return poc

    poc = buscar_poc_circl(cve_id)
    if poc:
        print(f"   💣 PoC ExploitDB: {poc['url']}")
        return poc

    print(f"   ℹ️  Nenhuma PoC pública para {cve_id}")
    return None


# =============================================================================
# DEDUPLICAÇÃO
# =============================================================================
def cve_ja_existe(cve_id: str) -> bool:
    try:
        res = supabase.table("news_articles").select("id").eq("cve_id", cve_id).limit(1).execute()
        return bool(getattr(res, "data", None))
    except Exception as e:
        print(f"⚠️  Falha ao verificar duplicidade de {cve_id}: {e}")
        return False


def esta_em_pending(cve_id: str) -> bool:
    try:
        res = supabase.table("pending_cves").select("id").eq("cve_id", cve_id).limit(1).execute()
        return bool(getattr(res, "data", None))
    except Exception as e:
        print(f"⚠️  Falha ao verificar pending de {cve_id}: {e}")
        return False


# =============================================================================
# VALIDAÇÃO DO PAYLOAD DA IA
# =============================================================================
def validar_analise(data: dict, cve_id: str, cvss=None):
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

    vetor        = normalizar_texto(data.get("vetor"),        "Desconhecido")
    complexidade = normalizar_texto(data.get("complexidade"), "Desconhecida")
    autenticacao = normalizar_texto(data.get("autenticacao"), "Desconhecida")

    if vetor        not in ALLOWED_VECTOR:     vetor        = "Desconhecido"
    if complexidade not in ALLOWED_COMPLEXITY: complexidade = "Desconhecida"
    if autenticacao not in ALLOWED_AUTH:       autenticacao = "Desconhecida"
    if severity     not in ALLOWED_SEVERITIES: severity     = severity_from_cvss(cvss)

    exploit_facilidade = normalizar_texto(data.get("exploit_facilidade"), "Não confirmado")

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


# =============================================================================
# ANÁLISE VIA GROQ
# =============================================================================
def analisar_com_groq(cve_id: str, summary: str, cvss=None, poc=None):
    print(f"🤖 Analisando {cve_id} com Groq...")

    severity_label = severity_from_cvss(cvss) if cvss else "unknown (sem CVSS ainda)"
    summary        = normalizar_texto(summary, "Sem resumo disponível.")

    poc_info = "Nenhuma PoC ou exploit público encontrado."
    if poc:
        stars_info = f" ({poc['stars']} stars)" if poc.get("stars") is not None else ""
        poc_info   = f"PoC disponível via {poc['source']}{stars_info}: {poc['url']}"

    system = (
        "Você é um analisador de CVEs especializado em segurança ofensiva e pentesting. "
        "Responda sempre em português do Brasil. "
        "Responda somente com JSON válido, sem nenhum texto adicional, sem markdown."
    )

    prompt = f"""Analise a vulnerabilidade abaixo e responda SOMENTE com um objeto JSON válido.
Sem texto antes ou depois, sem markdown, sem backticks.

CVE ID: {cve_id}
CVSS Score: {cvss if cvss is not None else 'Ainda não disponível'}
Severidade calculada: {severity_label}
Resumo original (EN): {summary}
Status de exploit/PoC: {poc_info}

Responda com exatamente este schema JSON:
{{
  "title": "string — CVE ID + produto afetado + tipo de vulnerabilidade em PT-BR, máx 80 chars",
  "description_pt": "string — 2 a 4 frases em PT-BR: o que é a falha, como pode ser explorada, qual o impacto real. Tom técnico e direto. Sem emojis.",
  "severity": "uma das opções: critical, high, medium, low, info, unknown",
  "tags": ["array de strings, ex: RCE, Windows, privilege-escalation, unauthenticated"],
  "vetor": "Rede | Local | Adjacente | Físico | Desconhecido",
  "complexidade": "Baixa | Média | Alta | Desconhecida",
  "autenticacao": "Nenhuma | Usuário | Administrador | Desconhecida",
  "exploit_facilidade": "frase curta sobre dificuldade de exploração, considerando se há PoC pública"
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
                    "model":    GROQ_MODEL,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user",   "content": prompt},
                    ],
                    "temperature": 0.1,
                    "max_tokens":  600,
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

            print(f"⚠️  Resposta inválida para {cve_id} (tentativa {attempt})")
            last_error = "validação falhou"

        except json.JSONDecodeError as e:
            print(f"❌ JSON inválido para {cve_id} (tentativa {attempt}): {e}")
            last_error = e
        except Exception as e:
            print(f"❌ Erro Groq para {cve_id} (tentativa {attempt}): {e}")
            last_error = e

        if attempt < GROQ_MAX_RETRIES:
            time.sleep(1.5 * attempt)

    print(f"❌ Falha final ao analisar {cve_id}: {last_error}")
    return None


# =============================================================================
# SUPABASE — PENDING_CVES
# =============================================================================
def adicionar_pending(cve: dict) -> None:
    cve_id = cve["id"]
    if esta_em_pending(cve_id):
        print(f"   ↩️  {cve_id} já está em pending_cves")
        return
    try:
        supabase.table("pending_cves").insert({
            "cve_id":           cve_id,
            "summary":          cve.get("summary", ""),
            "published_iso":    cve.get("published_iso"),
            "references_urls":  cve.get("references", []),
            "attempts":         0,
            "created_at":       now_iso(),
            "last_tried":       now_iso(),
        }).execute()
        print(f"   📥 {cve_id} adicionada em pending_cves")
    except Exception as e:
        print(f"   ❌ Erro ao inserir pending {cve_id}: {e}")


def incrementar_tentativa_pending(cve_id: str, attempts: int) -> None:
    try:
        supabase.table("pending_cves").update({
            "attempts":   attempts + 1,
            "last_tried": now_iso(),
        }).eq("cve_id", cve_id).execute()
    except Exception as e:
        print(f"⚠️  Erro ao atualizar tentativa pending {cve_id}: {e}")


def remover_pending(cve_id: str) -> None:
    try:
        supabase.table("pending_cves").delete().eq("cve_id", cve_id).execute()
    except Exception as e:
        print(f"⚠️  Erro ao remover pending {cve_id}: {e}")


def carregar_pending() -> list:
    try:
        res = (
            supabase.table("pending_cves")
            .select("*")
            .lt("attempts", PENDING_MAX_ATTEMPTS)
            .order("created_at")
            .execute()
        )
        return getattr(res, "data", []) or []
    except Exception as e:
        print(f"⚠️  Erro ao carregar pending_cves: {e}")
        return []


# =============================================================================
# SUPABASE — SAVE news_articles
# =============================================================================
def salvar_no_supabase(analise: dict, cve_id: str, cve: dict, poc) -> None:
    agora = now_iso()

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
        "awaiting_cvss":      cve.get("cvss") is None,
        "published":          cve.get("published_iso"),
        "source":             "NVD",
        "source_url":         NVD_URL_TEMPLATE.format(cve_id=cve_id),
        "references_urls":    cve.get("references", []),
        "poc_available":      poc is not None,
        "poc_url":            poc.get("url")    if poc else None,
        "poc_source":         poc.get("source") if poc else None,
        "is_published":       True,
        "created_at":         agora,
        "updated_at":         agora,
    }

    try:
        res = supabase.table("news_articles").insert(payload).execute()
        if getattr(res, "error", None):
            raise RuntimeError(str(res.error))
    except Exception as e:
        print(f"❌ Falha ao inserir {cve_id} no Supabase: {e}")
        raise


# =============================================================================
# DISCORD — NOTIFY
# =============================================================================
def enviar_discord(cve_id: str, analise: dict, cvss=None, poc=None) -> None:
    if not DISCORD_WEBHOOK:
        return

    severity_emoji = {
        "critical": "🔴",
        "high":     "🟠",
        "medium":   "🟡",
        "low":      "🟢",
        "info":     "⚪",
        "unknown":  "⚫",
    }.get(analise["severity"], "⚫")

    banner_critico = ""
    if analise["severity"] == "critical":
        banner_critico = "```\n⚠️  SEVERIDADE CRÍTICA — CVSS ≥ 9.0\n```\n"

    cvss_linha = (
        f"• CVSS: **{float(cvss):.1f}**\n"
        if cvss is not None
        else "• CVSS: **aguardando avaliação NVD**\n"
    )

    poc_linha = ""
    if poc:
        stars = f" ⭐ {poc['stars']}" if poc.get("stars") is not None else ""
        poc_linha = f"• PoC: [{poc['source'].upper()}{stars}]({poc['url']})\n"
    else:
        poc_linha = "• PoC: não encontrada publicamente\n"

    msg = (
        f"🚨 **NOVA CVE: {cve_id}** {severity_emoji}\n"
        f"{banner_critico}"
        f"**{analise['title']}**\n\n"
        f"{analise['description_pt']}\n\n"
        f"**Análise Pentest:**\n"
        f"{cvss_linha}"
        f"• Vetor: {analise.get('vetor', 'Desconhecido')}\n"
        f"• Complexidade: {analise.get('complexidade', 'Desconhecida')}\n"
        f"• Autenticação: {analise.get('autenticacao', 'Desconhecida')}\n"
        f"• Exploit: {analise.get('exploit_facilidade', 'Não confirmado')}\n"
        f"{poc_linha}\n"
        f"🔗 {NVD_URL_TEMPLATE.format(cve_id=cve_id)}"
    )

    try:
        resp = session.post(DISCORD_WEBHOOK, json={"content": msg}, timeout=15)
        if resp.status_code == 429:
            retry_after = float(resp.json().get("retry_after", 5))
            print(f"⚠️  Discord rate limit. Aguardando {retry_after}s...")
            time.sleep(retry_after + 1)
            session.post(DISCORD_WEBHOOK, json={"content": msg}, timeout=15)
        elif resp.status_code >= 400:
            print(f"⚠️  Discord {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        print(f"⚠️  Falha Discord {cve_id}: {e}")


# =============================================================================
# PROCESSAMENTO CENTRAL
# =============================================================================
def processar_cve(cve: dict) -> bool:
    cve_id = normalizar_texto(cve.get("id"))
    if not cve_id:
        return False

    if cve_ja_existe(cve_id):
        print(f"↩️  Já existe: {cve_id}")
        return False

    cvss = cve.get("cvss")

    if cvss is None:
        adicionar_pending(cve)
        return False

    if float(cvss) < CVSS_MINIMO:
        print(f"⏭️  {cve_id} CVSS={cvss} abaixo do mínimo ({CVSS_MINIMO})")
        return False

    print(f"\n{'='*60}")
    print(f"🔴 {cve_id} | CVSS={cvss} | {severity_from_cvss(cvss).upper()} | fonte={cve.get('cvss_fonte','?')}")

    # PoC antes do Groq para enriquecer o prompt
    poc = buscar_poc(cve_id)

    analise = analisar_com_groq(cve_id, cve.get("summary", ""), cvss=cvss, poc=poc)
    if not analise:
        return False

    try:
        salvar_no_supabase(analise, cve_id, cve, poc)
        if AUTO_PUBLISH:
            enviar_discord(cve_id, analise, cvss=cvss, poc=poc)
        print(f"✅ {cve_id} | PoC={'sim' if poc else 'não'} | auto_publish={AUTO_PUBLISH}")
        return True
    except Exception as e:
        print(f"❌ Erro ao salvar/enviar {cve_id}: {e}")
        return False


# =============================================================================
# REPROCESSAMENTO DE PENDING_CVES
# =============================================================================
def reprocessar_pending() -> int:
    pendentes = carregar_pending()
    if not pendentes:
        print("ℹ️  Nenhuma CVE pendente na fila")
        return 0

    print(f"\n🔄 Reprocessando {len(pendentes)} CVEs pendentes...")
    resolvidas = 0

    for row in pendentes:
        cve_id   = row["cve_id"]
        attempts = row.get("attempts", 0)

        if cve_ja_existe(cve_id):
            print(f"   ↩️  {cve_id} já processada — removendo de pending")
            remover_pending(cve_id)
            continue

        print(f"   🔎 {cve_id} (tentativa {attempts + 1}/{PENDING_MAX_ATTEMPTS})")

        cve = {
            "id":            cve_id,
            "summary":       row.get("summary", ""),
            "published_iso": row.get("published_iso"),
            "references":    row.get("references_urls", []),
            "cvss":          None,
            "cvss_fonte":    None,
        }

        cve = enriquecer_cvss(cve)

        if cve["cvss"] is None:
            incrementar_tentativa_pending(cve_id, attempts)
            if attempts + 1 >= PENDING_MAX_ATTEMPTS:
                print(f"   🗑️  {cve_id} — {PENDING_MAX_ATTEMPTS} tentativas esgotadas — descartando")
                remover_pending(cve_id)
            continue

        ok = processar_cve(cve)
        if ok:
            remover_pending(cve_id)
            resolvidas += 1

        time.sleep(1.2)

    print(f"   ✅ {resolvidas}/{len(pendentes)} pendentes resolvidas")
    return resolvidas


# =============================================================================
# PIPELINE PRINCIPAL
# =============================================================================
def processar_e_postar() -> None:
    init_clients()

    # 1. Coleta CVEs novas de hoje na NVD
    cves_brutas = coletar_cves_nvd()

    # 2. Enriquece CVSS via CIRCL/OSV onde NVD não forneceu
    cves = []
    for cve in cves_brutas:
        cve = enriquecer_cvss(cve)
        cves.append(cve)
        time.sleep(0.3)

    # 3. Processa CVEs de hoje
    processadas          = 0
    pendentes_adicionadas = 0

    for cve in cves:
        if cve.get("cvss") is None:
            adicionar_pending(cve)
            pendentes_adicionadas += 1
        else:
            ok = processar_cve(cve)
            if ok:
                processadas += 1
        time.sleep(1.2)

    # 4. Reprocessa fila pending (CVEs de horas anteriores que ganharam CVSS)
    resolvidas = reprocessar_pending()

    print(f"\n🏁 Pipeline concluído:")
    print(f"   CVEs novas processadas : {processadas}")
    print(f"   Enviadas ao pending     : {pendentes_adicionadas}")
    print(f"   Pendentes resolvidas    : {resolvidas}")


# =============================================================================
# ENTRYPOINT
# =============================================================================
if __name__ == "__main__":
    processar_e_postar()
