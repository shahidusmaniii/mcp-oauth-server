# Honasa MCP OAuth Server

A FastAPI-based OAuth 2.0 Authorization Server that protects an MCP (Model Context Protocol) server with Google OIDC authentication and JWT tokens.

## Overview

This application serves dual roles:
- **Authorization Server (AS)**: Issues RS256 JWT access tokens after Google OIDC authentication
- **OAuth Protected Resource (PRM)**: MCP server accessible at `/mcp` with JWT token validation

## Features

- Google OIDC integration for user authentication
- PKCE (Proof Key for Code Exchange) flow support
- RS256 JWT token issuance and validation
- Weather API tool via MCP protocol
- Dynamic client registration
- RFC-9728 compliant WWW-Authenticate challenges
- OpenID Connect discovery endpoints

## Quick Start

### Prerequisites

- Python 3.12
- Google OAuth credentials
- OpenWeatherMap API key

### Setup

1. **Install dependencies**:
   ```bash
   uv venv
   source .venv/bin/activate
   uv pip install -r requirements.txt
   ```

2. **Configure environment**:
   Create a `.env` file:
   ```env
   BASE_URL=http://localhost:8000
   GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   WEATHER_API_KEY=your_openweathermap_key
   ALLOWED_EMAILS=you@example.com,teammate@example.com
   ```

3. **Run the server**:
   ```bash
   uv run uvicorn app.main:app --reload --port 8000
   ```

## API Endpoints

### OAuth/OpenID Connect

- `GET /authorize` - Start OAuth authorization flow
- `GET /oidc/callback` - Handle Google OIDC callback
- `POST /token` - Exchange authorization code for access token
- `POST /register` - Dynamic client registration

### Discovery

- `GET /.well-known/openid-configuration` - OIDC discovery metadata
- `GET /.well-known/jwks.json` - JSON Web Key Set
- `GET /.well-known/oauth-protected-resource` - Protected resource metadata

### MCP Server

- `/mcp` - MCP server endpoint (requires Bearer token)
- Available tool: `fetch_weather(city: str)` - Get weather data for a city

## Usage Example

### 1. Register a Client

```bash
curl -X POST http://localhost:8000/register \
  -H 'Content-Type: application/json' \
  -d '{"redirect_uris":["http://127.0.0.1:5555/callback"],"scope":"mcp.basic"}'
```

### 2. Generate PKCE Parameters

```python
import os, base64, hashlib
code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip("=")
```

### 3. Start Authorization Flow

Visit in browser:
```
http://localhost:8000/authorize?client_id=<client_id>&redirect_uri=http://127.0.0.1:5555/callback&scope=mcp.basic&state=xyz&code_challenge=<challenge>&code_challenge_method=S256
```

### 4. Exchange Code for Token

```bash
curl -X POST http://localhost:8000/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=authorization_code&code=<code>&code_verifier=<verifier>&client_id=<client_id>"
```

### 5. Access MCP Server

```bash
curl -H "Authorization: Bearer <access_token>" http://localhost:8000/mcp/mcp
```

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│     Client      │───▶│  OAuth Server    │───▶│  Google OIDC    │
│                 │    │  (this app)      │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │
         │                       ▼
         │              ┌──────────────────┐
         └─────────────▶│   MCP Server     │
                        │  (/mcp endpoint) │
                        └──────────────────┘
```

## Project Structure

```
app/
├── __init__.py
├── auth.py          # OAuth/OIDC endpoints and logic
├── config.py        # Environment configuration
├── main.py          # FastAPI app and MCP integration
├── mcp_tools.py     # MCP tools (weather API)
└── security.py      # JWT handling and verification
clients.json         # Registered OAuth clients
requirements.txt     # Python dependencies
```

## Security Features

- **PKCE Flow**: Protects against authorization code interception
- **Single-use Codes**: Authorization codes expire after use (5 minutes TTL)
- **JWT Signature Verification**: RS256 with rotating keys
- **Email Allowlist**: Restricts access to specified email addresses
- **Scope Validation**: Ensures proper scope-based access control

## Known Limitations

- In-memory storage (auth codes, client data) - will reset on restart
- Google ID token signature not verified (security gap)
- Ephemeral signing keys - tokens become invalid on restart
- No refresh token support

## Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `BASE_URL` | Server base URL | No | `http://localhost:8000` |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | Yes | - |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | Yes | - |
| `WEATHER_API_KEY` | OpenWeatherMap API key | Yes | - |
| `ALLOWED_EMAILS` | Comma-separated allowed emails | No | Empty |
| `REDIRECT_PATH` | OAuth callback path | No | `/oidc/callback` |

## License

This project is for demonstration purposes.