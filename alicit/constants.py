"""Shared constants and default paths for AIlicit.

Every value can be overridden via environment variable where noted.
Runtime data files live in the repository's ``data/`` directory.
"""

import os

# Load .env from the repo root if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))
except ImportError:
    pass

# ------------------------------------------------------------------
# Repository layout (data files live outside the package)
# ------------------------------------------------------------------
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(REPO_ROOT, "data")

os.makedirs(DATA_DIR, exist_ok=True)

# ------------------------------------------------------------------
# Microsoft OAuth app (malicious OAuth app used for the attack chain)
# ------------------------------------------------------------------
CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "756b1e2d-0cd5-4ada-8bcc-a415b949216e")
CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv(
    "OAUTH_REDIRECT_URI",
    "https://c5b3-2601-19b-d86-32d0-f9da-f715-9cf6-ec04.ngrok-free.app/oauth/callback",
)

# OAuth scopes requested in the authorization URL (consent screen)
OAUTH_SCOPES = os.getenv(
    "OAUTH_SCOPES",
    "offline_access User.Read Mail.ReadWrite Mail.Send Files.ReadWrite Contacts.ReadWrite Calendars.ReadWrite Directory.Read.All",
)

# ------------------------------------------------------------------
# Groq API (Llama models for BEC analysis & crafting)
# ------------------------------------------------------------------
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
SCOUT_MODEL = "openai/gpt-oss-20b"        # For financial exposure analysis

ORCAROUTER_MODEL = "deepseek/deepseek-v4-flash-free"
ORCAROUTER_ENDPOINT = "https://api.orcarouter.ai/v1/chat/completions"
ORCAROUTER_API_KEY = os.getenv("ORCAROUTER_API_KEY", "")

# ------------------------------------------------------------------
# Foundation-Sec-1.1-8B — primary reasoning / path-selection analyst.
# Optional layer: if not configured, Groq Llama-3.3-70b is used as
# the fallback selector, and if that is also missing the engine falls
# back to purely deterministic (score-based) selection.
# Expects an OpenAI-compatible endpoint (local Ollama on 11434;
# override with SEC_BASE_URL, e.g. http://localhost:8080/v1 if you
# front it with llama.cpp. The OAuth capture listener uses 8081).
# ------------------------------------------------------------------
SEC_API_KEY = os.getenv("SEC_API_KEY", "ollama")
SEC_BASE_URL = os.getenv("SEC_BASE_URL", "http://localhost:11434/v1")
SEC_MODEL = os.getenv("SEC_MODEL", "hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q8_0-GGUF:Q8_0")

# ------------------------------------------------------------------
# Replanner — Qwen3.5-9B-Uncensored, used by the ReAct privesc agent
# to re-plan after a failed step (and as the freestyle explorer).
# Same Ollama endpoint by default; all LLM calls are serialized so the
# two models never hit the API concurrently (see privesc.llm_call).
# ------------------------------------------------------------------
REPLAN_API_KEY = os.getenv("REPLAN_API_KEY", SEC_API_KEY)
REPLAN_BASE_URL = os.getenv("REPLAN_BASE_URL", SEC_BASE_URL)
REPLAN_MODEL = os.getenv("REPLAN_MODEL", "hf.co/HauhauCS/Qwen3.5-9B-Uncensored-HauhauCS-Aggressive:Q8_0")

# Backwards-compatible aliases (legacy QWEN_* names).
QWEN_API_KEY = SEC_API_KEY
QWEN_BASE_URL = SEC_BASE_URL
QWEN_MODEL = SEC_MODEL

# External address used as the forwarding target when auto-executing a
# mail-forwarding persistence path. Override for your lab.
PRIVESC_CAPTURE_EMAIL = os.getenv("PRIVESC_CAPTURE_EMAIL", "attacker@demo.com")

# ------------------------------------------------------------------
# Default data file locations
# ------------------------------------------------------------------
TOKEN_FILE = os.getenv("TOKEN_FILE", os.path.join(DATA_DIR, "tokens.json"))
CAMPAIGN_FILE = os.getenv("CAMPAIGN_FILE", os.path.join(DATA_DIR, "campaigns.json"))
CAPTURE_FILE = os.getenv("CAPTURE_FILE", os.path.join(DATA_DIR, "captured_tokens.txt"))
