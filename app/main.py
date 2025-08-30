from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse

from mcp.server.fastmcp import FastMCP
from mcp.server.auth.settings import AuthSettings

from . import auth, config, mcp_tools, security

# --- Lifespan Manager for MCP Session ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start FastMCP’s background task group for Streamable HTTP
    async with mcp.session_manager.run():
        yield

# --- Initialize FastAPI App ---
app = FastAPI(lifespan=lifespan)

# --- Initialize FastMCP ---
mcp = FastMCP(
    "Demo OAuth MCP",
    token_verifier=security.LocalJWTVerifier(),
    auth=AuthSettings(
        issuer_url=config.ISSUER,
        resource_server_url=config.MCP_URL,
        required_scopes=config.REQUIRED_SCOPES,
    ),
)

# Register the MCP tool
mcp.tool()(mcp_tools.fetch_weather)

# Mount the MCP ASGI sub-app
app.mount("/mcp", mcp.streamable_http_app())


app.include_router(auth.router)


# --- Middleware ---
class ForceSingleWWWAuth(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response: Response = await call_next(request)
        # Normalize for both "/mcp/mcp" and "/mcp/mcp/..." (after redirects) 
        if response.status_code == 401 and (
            request.url.path == "/mcp/mcp"
            or request.url.path.startswith("/mcp/mcp/")
        ):
            # Exactly one Bearer challenge pointing at the root PRM per RFC 9728
            response.headers["WWW-Authenticate"] = (
                f'Bearer resource_metadata="{config.PRM_URL_FOR_THIS_PATH}"'
            )
            # Optional, but handy:
            response.media_type = "application/json"
            response.body = b'{"error":"invalid_token","error_description":"Authentication required"}'
        return response

app.add_middleware(ForceSingleWWWAuth)


# --- Well-Known Endpoints ---
@app.get("/.well-known/jwks.json")
def jwks():
    """Exposes the public key for verifying JWTs."""
    return {"keys": [security.jwk_from_public_key()]}

@app.get("/.well-known/openid-configuration")
def openid_config():
    """Provides OpenID Connect discovery information."""
    return {
        "issuer": config.ISSUER,
        "authorization_endpoint": f"{config.BASE_URL}/authorize",
        "token_endpoint": f"{config.BASE_URL}/token",
        "registration_endpoint": f"{config.BASE_URL}/register",
        "jwks_uri": f"{config.BASE_URL}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "scopes_supported": config.REQUIRED_SCOPES,
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
    }

@app.get("/.well-known/oauth-protected-resource")
def prm_root():
    """Provides metadata about the protected resource (the MCP server)."""
    return {
        "authorization_servers": [config.ISSUER],
        "resource": config.MCP_URL,
        "scopes_supported": config.REQUIRED_SCOPES,
        "token_types_supported": ["Bearer"],
    }

@app.get("/.well-known/oauth-authorization-server")
def oauth_as_meta():
    """Alias for the OpenID configuration endpoint."""
    return openid_config()


@app.get("/")
def root():
    """A simple health check or info endpoint."""
    return {"ok": True, "issuer": config.ISSUER, "mcp": config.BASE_URL}

