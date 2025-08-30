import os
from dotenv import load_dotenv
load_dotenv()  

def _env(name: str, default: str | None = None, required: bool = False) -> str:
    val = os.getenv(name, default)
    if required and not val:
        raise RuntimeError(f"Missing required env var: {name}")
    return val or ""

# --- Base URLs ---
BASE_URL = _env("BASE_URL", "http://localhost:8000")
REDIRECT_PATH = _env("REDIRECT_PATH", "/oidc/callback")
REDIRECT_URI = f"{BASE_URL}{REDIRECT_PATH}"

# --- MCP ---
MCP_URL = f"{BASE_URL}/mcp/mcp"
ISSUER = BASE_URL
PRM_URL_FOR_THIS_PATH = f"{BASE_URL}/.well-known/oauth-protected-resource"
REQUIRED_SCOPES = ["mcp.basic"]

# --- Google OIDC ---
GOOGLE_CLIENT_ID = _env("GOOGLE_CLIENT_ID", required=True)
GOOGLE_CLIENT_SECRET = _env("GOOGLE_CLIENT_SECRET", required=True)
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# --- External APIs ---
WEATHER_API_KEY = _env("WEATHER_API_KEY", required=True)

# --- Access control ---
ALLOWED_EMAILS = {
    e.strip() for e in _env("ALLOWED_EMAILS", "").split(",") if e.strip()
} 


