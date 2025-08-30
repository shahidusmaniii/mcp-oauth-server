import secrets
import time
import json
import pathlib
import hashlib
import base64
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse

from . import config
from . import security

router = APIRouter()

# --- In-memory storage for OAuth flow ---
# In production, this should be replaced with a database like Redis.
auth_codes = {}  # code -> {sub, code_challenge, scopes, exp, client_id, redirect_uri}
code_states = {}  # state -> {client_id, redirect_uri, scope, code_challenge, ...}

# --- Client Management ---
CLIENTS_FILE = pathlib.Path("./clients.json")


def load_clients():
    if CLIENTS_FILE.exists():
        with CLIENTS_FILE.open("r") as f:
            return json.load(f)
    return {}


def save_clients():
    tmp = CLIENTS_FILE.with_suffix(".tmp")
    with tmp.open("w") as f:
        json.dump(clients, f)
    tmp.replace(CLIENTS_FILE)


clients = load_clients()

@router.get("/")
def root():
    """A simple health check or info endpoint."""
    return {"ok": True, "issuer": config.ISSUER, "mcp": config.MCP_URL}

@router.post("/register")
async def register_client(req: Request):
    """Dynamically register a new OAuth client."""
    body = await req.json()
    redirect_uris = body.get("redirect_uris", [])
    if not redirect_uris:
        raise HTTPException(status_code=400, detail="redirect_uris required")

    client_id = secrets.token_urlsafe(24)
    clients[client_id] = {
        "redirect_uris": redirect_uris,
        "token_auth_method": body.get("token_endpoint_auth_method", "none"),
        "scope": body.get("scope", " ".join(config.REQUIRED_SCOPES)),
        "grant_types": body.get("grant_types", ["authorization_code"]),
    }
    save_clients()

    return JSONResponse({
        "client_id": client_id,
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": clients[client_id]["token_auth_method"],
        "grant_types": clients[client_id]["grant_types"],
        "scope": clients[client_id]["scope"],
    }, status_code=201)


@router.get("/authorize")
def authorize(req: Request):
    """Start the OAuth2 authorization flow."""
    qs = req.query_params
    client_id = qs.get("client_id")
    redirect_uri = qs.get("redirect_uri")

    if not client_id or client_id not in clients or redirect_uri not in clients[client_id]["redirect_uris"]:
        raise HTTPException(status_code=400, detail="Invalid client_id or redirect_uri")

    if not qs.get("code_challenge") or qs.get("code_challenge_method") != "S256":
        raise HTTPException(status_code=400, detail="code_challenge with S256 method is required")

    state = qs.get("state", secrets.token_urlsafe(16))
    code_states[state] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": qs.get("scope", " ".join(config.REQUIRED_SCOPES)),
        "code_challenge": qs.get("code_challenge"),
        "code_challenge_method": qs.get("code_challenge_method"),
        "resource": qs.get("resource", config.MCP_URL),
        "ts": time.time(),
    }

    # Redirect to Google for authentication
    google_auth_params = {
        "response_type": "code",
        "client_id": config.GOOGLE_CLIENT_ID,
        "redirect_uri": config.REDIRECT_URI,
        "scope": "openid email profile",
        "state": state,
        "prompt": "consent",
    }
    return RedirectResponse(f"{config.GOOGLE_AUTH_URL}?{urlencode(google_auth_params)}")


@router.get("/oidc/callback")
async def google_callback(req: Request):
    """Handle the callback from Google's OAuth flow."""
    qs = req.query_params
    code = qs.get("code")
    state = qs.get("state")
    if not code or state not in code_states:
        raise HTTPException(status_code=400, detail="Invalid state or code from provider")

    # Exchange Google's code for a token
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": config.GOOGLE_CLIENT_ID,
        "client_secret": config.GOOGLE_CLIENT_SECRET,
        "redirect_uri": config.REDIRECT_URI,
    }
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(config.GOOGLE_TOKEN_URL, data=token_data)
        token_json = token_resp.json()

    id_token = token_json.get("id_token")
    if not id_token:
        raise HTTPException(status_code=400, detail="id_token not found in response")

    # Decode the ID token to get user info (without signature verification for this step)
    try:
        g_claims = jwt.decode(id_token, options={"verify_signature": False})
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=400, detail=f"Invalid id_token: {e}")

    user_email = g_claims.get("email")
    if user_email not in config.ALLOWED_EMAILS:
        raise HTTPException(status_code=403, detail=f"Access denied for email: {user_email}")

    sub = f"google:{g_claims.get('sub')}"
    local_state = code_states.pop(state)

    # Generate our local authorization code
    auth_code = secrets.token_urlsafe(24)
    auth_codes[auth_code] = {
        "sub": sub,
        "code_challenge": local_state["code_challenge"],
        "scopes": local_state["scope"].split(),
        "resource": local_state["resource"],
        "exp": time.time() + 300,  # 5-minute expiry
        "client_id": local_state["client_id"],
        "redirect_uri": local_state["redirect_uri"],
    }

    # Redirect back to the original client application
    redirect_params = {'code': auth_code, 'state': state}
    return RedirectResponse(f"{local_state['redirect_uri']}?{urlencode(redirect_params)}")


@router.post("/token")
async def issue_token(req: Request):
    """Exchange an authorization code for an access token."""
    form = await req.form()
    code = form.get("code")
    code_verifier = form.get("code_verifier")
    client_id = form.get("client_id")

    if not all([code, code_verifier, client_id]):
        raise HTTPException(status_code=400, detail="Missing required parameters")

    if client_id not in clients:
        raise HTTPException(status_code=401, detail="invalid_client")

    if form.get("grant_type") != "authorization_code":
        raise HTTPException(status_code=400, detail="unsupported_grant_type")

    record = auth_codes.pop(code, None)
    if not record or record['exp'] < time.time():
        raise HTTPException(status_code=400, detail="Invalid or expired code")

    # Verify PKCE S256 code challenge
    digest = hashlib.sha256(code_verifier.encode()).digest()
    expected_challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    if expected_challenge != record["code_challenge"]:
        raise HTTPException(status_code=400, detail="Invalid code_verifier")

    now = int(time.time())
    claims = {
        "iss": config.ISSUER,
        "sub": record["sub"],
        "aud": record["resource"],
        "iat": now,
        "exp": now + 3600,  # 1-hour expiry
        "scope": " ".join(record["scopes"]),
        "client_id": record["client_id"],
    }
    headers = {"kid": security.KID}
    access_token = jwt.encode(claims, security.private_pem, algorithm="RS256", headers=headers)

    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": " ".join(record["scopes"]),
    }, headers={"Cache-Control": "no-store"})

