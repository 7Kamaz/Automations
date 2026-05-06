# 🤖 Kamaz Intel Bot — CVE Automation Pipeline

> Bot de inteligência em segurança ofensiva que monitora, enriquece e notifica sobre vulnerabilidades críticas publicadas diariamente, com análise automatizada em PT-BR via LLM.

---

## 📌 Sobre o Projeto

O **Kamaz Intel Bot** é um pipeline de automação em Python que coleta CVEs publicadas **no dia atual** pela NVD, enriquece os dados com múltiplas fontes de CVSS, busca PoCs públicas no GitHub e ExploitDB, e gera análises técnicas completas em português do Brasil usando o modelo **Llama 3.3 70B via Groq**. Os resultados são persistidos no Supabase e notificados em tempo real via Discord.

O pipeline roda de forma autônoma via **GitHub Actions**, sendo acionado automaticamente a cada hora.

---

## ⚙️ Pipeline de Execução

```
NVD API v2.0
     │
     ▼
Filtra CVEs publicadas HOJE (pubStartDate/pubEndDate) com CVSS ≥ 7.0
     │
     ├──► CIRCL CVE API  ──┐
     │                     ├──► Enriquecimento de CVSS (hierarquia: NVD → CIRCL → OSV)
     └──► OSV.dev API   ──┘
     │
     ▼
pending_cves (Supabase)
     └──► CVEs sem CVSS entram na fila e são reprocessadas na próxima execução
     │
     ▼
GitHub Search API  ──► Busca PoC/exploits públicos (fallback: CIRCL/ExploitDB)
     │
     ▼
Groq API (Llama 3.3 70B)
     └──► Análise completa em PT-BR: descrição, vetor, complexidade, facilidade de exploit
     │
     ▼
Supabase  ──► Persiste em `news_articles` (service role bypassa RLS)
     │
     ▼
Discord Webhook  ──► Notificação formatada por severidade (crítica recebe banner especial)
```

---

## 🛠️ Tecnologias e Ferramentas

| Categoria | Tecnologia | Versão |
|---|---|---|
| Linguagem | Python | 3.10+ |
| HTTP Client | `requests` + `requests.Session` | latest |
| LLM | Groq API — Llama 3.3 70B Versatile | `llama-3.3-70b-versatile` |
| Banco de Dados | Supabase (PostgreSQL) | latest |
| CI/CD | GitHub Actions | — |
| Env vars | `python-dotenv` | latest |
| SDK Supabase | `supabase-py` | latest |

### APIs Externas Consumidas

| API | Função | Endpoint |
|---|---|---|
| **NVD API v2.0** | Fonte principal de CVEs | `services.nvd.nist.gov/rest/json/cves/2.0/` |
| **CIRCL CVE API** | CVSS alternativo + PoC via ExploitDB | `cve.circl.lu/api/cve/{id}` |
| **OSV.dev** | CVSS alternativo (CVSS_V3) | `api.osv.dev/v1/query` |
| **GitHub Search API** | Busca de PoC/exploits públicos | `api.github.com/search/repositories` |
| **Groq API** | Análise LLM em PT-BR | `api.groq.com/openai/v1/chat/completions` |
| **Discord Webhook** | Notificações em tempo real | webhook configurado por env var |

---

## 📁 Estrutura do Repositório

```
Automations/
├── bot_cve.py              # Pipeline principal (812 linhas)
├── requirements.txt        # Dependências Python
├── .github/
│   └── workflows/          # GitHub Actions (execução automática)
└── .gitattributes
```

---

## 🔧 Instalação e Configuração

### 1. Clone o repositório

```bash
git clone https://github.com/7Kamaz/Automations.git
cd Automations
```

### 2. Instale as dependências

```bash
pip install -r requirements.txt
```

### 3. Configure as variáveis de ambiente

Crie um arquivo `.env` na raiz do projeto:

```env
# Supabase
SUPABASE_URL=https://seu-projeto.supabase.co
SUPABASE_SERVICE_ROLE_KEY=sua_service_role_key

# Groq
GROQ_API_KEY=sua_groq_api_key
GROQ_MODEL=llama-3.3-70b-versatile   # opcional, é o padrão

# NVD
NVD_API_KEY=sua_nvd_api_key
NVD_RESULTS_PER_PAGE=2000             # opcional

# GitHub
TOKEN_GITHUB=seu_github_token

# Discord
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...

# Comportamento
CVSS_MINIMO=7.0                       # opcional, padrão: 7.0
AUTO_PUBLISH=true                     # opcional, padrão: false
GROQ_TIMEOUT=60                       # opcional
GROQ_MAX_RETRIES=3                    # opcional
PENDING_MAX_ATTEMPTS=24               # opcional
```

> ⚠️ Nunca commite o arquivo `.env`. Adicione ao `.gitignore`.

### 4. Execute manualmente

```bash
python bot_cve.py
```

---

## 🗄️ Esquema do Banco de Dados (Supabase)

### Tabela `news_articles`

| Campo | Tipo | Descrição |
|---|---|---|
| `cve_id` | text | Identificador único da CVE |
| `title` | text | Título gerado pelo LLM (max 80 chars) |
| `description_pt` | text | Análise técnica em PT-BR |
| `severity` | text | `critical`, `high`, `medium`, `low`, `info`, `unknown` |
| `tags` | text[] | Tags de categorização (ex: RCE, Windows, privilege-escalation) |
| `cvss` | float | Score CVSS |
| `vetor` | text | Vetor de ataque |
| `complexidade` | text | Complexidade de exploração |
| `autenticacao` | text | Requisito de autenticação |
| `exploit_facilidade` | text | Análise de facilidade de exploit |
| `poc_available` | boolean | Indica se há PoC pública |
| `poc_url` | text | URL da PoC encontrada |
| `poc_source` | text | Origem da PoC (`github`, `exploitdb`) |
| `awaiting_cvss` | boolean | True se ainda aguarda avaliação CVSS |
| `references_urls` | text[] | Referências da NVD |
| `source_url` | text | Link direto no NVD |

### Tabela `pending_cves`

Fila de CVEs sem CVSS aguardando reprocessamento. Máximo de `PENDING_MAX_ATTEMPTS` tentativas (padrão: 24 horas) antes de descarte automático.

---

## 🔄 Automação com GitHub Actions

O pipeline é executado automaticamente via **GitHub Actions** com schedule configurado. Todas as secrets são armazenadas no repositório (Settings → Secrets and variables → Actions):

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `GROQ_API_KEY`
- `NVD_API_KEY`
- `TOKEN_GITHUB`
- `DISCORD_WEBHOOK_URL`
- `AUTO_PUBLISH`

---

## 🧠 Lógica de Análise com LLM

O bot constrói um prompt estruturado com todos os dados enriquecidos antes de acionar o Groq, garantindo que o modelo receba contexto completo (CVSS, status de PoC, descrição original) para gerar:

- **Título** técnico e objetivo em PT-BR
- **Descrição** com impacto real e vetor de exploração
- **Classificação** de severidade validada
- **Tags** para categorização e busca
- **Análise de exploit** considerando existência de PoC pública

O sistema usa `temperature: 0.1` para máxima consistência e inclui até 3 tentativas com backoff exponencial em caso de falha ou resposta inválida.

---

## 📊 Filtros e Critérios

- Coleta apenas CVEs **publicadas no dia atual** (sem capturar modificadas/antigas)
- CVSS mínimo configurável (padrão: **≥ 7.0** — High e Critical)
- Hierarquia de CVSS: **NVD → CIRCL → OSV**
- CVEs sem CVSS entram em fila de reprocessamento por até 24h
- Deduplicação automática por `cve_id` antes de qualquer processamento

---

## 📬 Notificações no Discord

As mensagens são formatadas por nível de severidade com emojis visuais. CVEs com CVSS ≥ 9.0 recebem um **banner especial de alerta crítico**. Cada notificação inclui:

- Score CVSS e severidade
- Vetor, complexidade e requisito de autenticação
- Status de PoC pública com link e número de stars (GitHub)
- Link direto para a CVE no NVD

---

## 📦 Dependências (`requirements.txt`)

```
requests
python-dotenv
groq
supabase
```

---

## 📄 Licença

Distribuído sob a licença **MIT**. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

---

## 👤 Autor

**Kamaz** — [@7Kamaz](https://github.com/7Kamaz)
