import os
import base64
import jwt
import time
from typing import Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp.server.auth.provider import AccessToken, TokenVerifier
from . import config

# --- RSA Key Generation for JWT Signing ---
# In a production environment, you would load this from a secure location,
# not generate it on startup.
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

private_pem = rsa_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

public_pem = rsa_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# A unique identifier for the key
KID = base64.urlsafe_b64encode(os.urandom(8)).decode().rstrip("=")

def jwk_from_public_key():
    """Generates a JSON Web Key (JWK) from the public RSA key."""
    numbers = rsa_key.public_key().public_numbers()
    e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": KID,
        "n": base64.urlsafe_b64encode(n_bytes).decode().rstrip("="),
        "e": base64.urlsafe_b64encode(e_bytes).decode().rstrip("="),
    }

# --- Custom Token Verifier ---
class LocalJWTVerifier(TokenVerifier):
    """Verifies JWTs that were issued by this server."""
    async def verify_token(self, token: str) -> Optional[AccessToken]:
        try:
            claims = jwt.decode(
                token,
                public_pem,
                algorithms=["RS256"],
                audience=config.MCP_URL,
                issuer=config.ISSUER,
            )
        except jwt.PyJWTError:
            return None

        # Ensure required scopes are present
        scopes = set(claims.get("scope", "").split())
        if not set(config.REQUIRED_SCOPES).issubset(scopes):
            return None

        # Check token expiration
        if int(claims.get("exp", 0)) <= int(time.time()):
            return None

        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id", "")),
            scopes=sorted(list(scopes)),
            expires_at=int(claims.get("exp")),
            resource=config.MCP_URL,
        )

