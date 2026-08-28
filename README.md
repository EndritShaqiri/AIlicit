# AIlicit

**AI-powered OAuth phishing & BEC post-exploitation toolkit** for authorized red-team / research.
Built for the BSides Orlando talk *"AIlicit: AI-Powered Identity Abuse — Attack Chain, Detection, and Defense."*

The tool chains three phases:

1. **Recon + Phish** — OSINT discovery of a target's public emails (Hunter.io, Google News, LinkedIn, DNS), then AI-generated contextual phishing emails with a malicious Microsoft OAuth link.
2. **Capture** — a redirect listener that grabs the `code` / `access_token` the victim's browser sends to the attacker's OAuth app.
3. **Post-exploit** — exchange the code for tokens, run parallel Microsoft Graph recon, use Llama-4 models (via Groq) to analyze mailbox financial exposure and craft a Business Email Compromise (BEC) message, then send it from the compromised account.

A Flask + SocketIO **dashboard** ties it together with a live campaign UI.

> Authorized testing only. All network traffic and token exchange uses your own credentials.

## Structure

```
alicit/
  __init__.py       package metadata
  __main__.py       python -m alicit listener
  constants.py      shared config: OAuth app, Groq models, data paths (env-overridable)
  reclist.py        Phase 0+1: OSINTRecon, PhishingEmailGenerator, StealthEmailSender, OAuthPhishAgent
  postexp.py        Phase 2: TokenManager, Graph recon, Llama analysis & BEC craft/send
  dashboard.py      Flask + SocketIO web UI (port 5000)
  listener.py       OAuth code/token capture endpoint (port 8080)
scripts/
  test_hunter.py    quick Hunter.io domain-search sanity check
data/               runtime artifacts: tokens.json, campaigns.json, captured_tokens.txt, capture_*.log
output/             per-campaign logs and results JSON
tests/              smoke tests
```

## Setup

Python ≥ 3.10 (developed on 3.11).

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   |   macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt      # or: pip install -e .
```

Create `.env` from `.env.example` (or export the vars in your shell):

| Variable | Used by | Notes |
|---|---|---|
| `GROQ_API_KEY` | postexp, dashboard | **required** — Llama-4 Scout & Maverick |
| `OPENAI_API_KEY` | reclist | optional, for LLM red-team wrapper |
| `HUNTER_API_KEY` | reclist | email discovery |
| `NEWS_API_KEY` | reclist | Google News / news search |
| `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` / `OAUTH_REDIRECT_URI` | all | malicious OAuth app (defaults in `constants.py`) |
| `SMTP_PASSWORD` | reclist | send-email credentials (see `Config`) |

## Usage

```bash
# 1. Start the capture listener (public URL behind ngrok/tunnel -> port 8080)
python -m alicit.listener            # or: python -m alicit listener

# 2. Run recon + phishing campaign (Phase 0+1)
alicit-recl                          # interactive menu, or python -m alicit.reclist

# 3. Post-exploitation with captured token (Phase 2)
alicit-postexp                       # interactive menu: analyze mailbox, craft & send BEC

# 4. Web dashboard (Phase 0-2 in one UI)
alicit-dashboard                     # http://localhost:5000
```

## Tests

```bash
GROQ_API_KEY=anything pytest tests/ -v
```
