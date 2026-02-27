# ============================================================
#  config.py — Application Configuration
#  All values are read from environment variables.
#  Run:  cp .env.example .env  then fill in your keys.
# ============================================================

import os
from dotenv import load_dotenv

load_dotenv()


def _require(name: str) -> str:
    """Return env var or raise a clear error at startup."""
    val = os.getenv(name)
    if not val:
        raise EnvironmentError(
            f"Required environment variable '{name}' is not set. "
            "Copy .env.example → .env and add your keys."
        )
    return val


def _optional(name: str, default: str = "") -> str:
    return os.getenv(name, default)


# ── Flask ─────────────────────────────────────────────────────
FLASK_SECRET_KEY = _optional("FLASK_SECRET_KEY", "dev-secret-change-me")

# ── Google APIs ───────────────────────────────────────────────
GOOGLE_CLIENT_ID     = _optional("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = _optional("GOOGLE_CLIENT_SECRET")
PAGESPEED_API_KEY    = _optional("PAGESPEED_API_KEY")
SAFE_BROWSING_API_KEY = _optional("SAFE_BROWSING_API_KEY")

# ── AI Providers ──────────────────────────────────────────────
GEMINI_API_KEY     = _optional("GEMINI_API_KEY")
GEMINI_MODEL       = "gemini-2.0-flash-exp"

GROQ_API_KEY       = _optional("GROQ_API_KEY")
GROQ_API_URL       = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL         = "mixtral-8x7b-32768"

OPENROUTER_API_KEY = _optional("OPENROUTER_API_KEY")
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL   = "mistralai/mistral-7b-instruct"

COHERE_API_KEY     = _optional("COHERE_API_KEY")
COHERE_API_URL     = "https://api.cohere.ai/v1/generate"
COHERE_MODEL       = "command"

# GLM-5: comma-separated list in env, e.g. "key1,key2,key3"
GLM5_API_KEYS = [k.strip() for k in _optional("GLM5_API_KEYS").split(",") if k.strip()]
GLM5_API_URL  = "https://open.bigmodel.cn/api/paas/v4/chat/completions"
GLM5_MODEL    = "glm-4"

# ── Data APIs ────────────────────────────────────────────────
APIFY_API_KEY    = _optional("APIFY_API_KEY")
APIFY_API_URL    = "https://api.apify.com/v2/acts"

APYHUB_API_KEY   = _optional("APYHUB_API_KEY")
APYHUB_API_URL   = "https://api.apyhub.com"

FETCHSERP_API_KEY = _optional("FETCHSERP_API_KEY")
FETCHSERP_API_URL = "https://api.fetchserp.com"

PIXAZO_API_KEY   = _optional("PIXAZO_API_KEY")

# ── External service endpoints ────────────────────────────────
PAGESPEED_API    = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
SAFE_BROWSING_API = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
