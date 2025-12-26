"""
Ordr Auth Validator Service - Debug Version

Logs token details to help troubleshoot audience mismatch.
Accepts multiple audience formats.
"""

import os
import logging
from datetime import datetime
from typing import Optional
from functools import lru_cache

from fastapi import FastAPI, HTTPException, Header, Response
from fastapi.middleware.cors import CORSMiddleware
import jwt
from jwt import PyJWKClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ordr-auth")

# =============================================================================
# CONFIGURATION
# =============================================================================

AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "d63e5ccd-bd26-4b10-91b7-2dd7052577cb")
AZURE_JWKS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
# Accept both Azure AD issuer formats
AZURE_ISSUER_PREFIXES = [
    "https://login.microsoftonline.com/",  # v2.0
    "https://sts.windows.net/",             # v1.0
]
TEST_MODE = os.environ.get("TEST_MODE", "false").lower() == "true"

# Accept multiple audience formats
VALID_AUDIENCES = [
    AZURE_CLIENT_ID,                                    # Just client ID
    f"api://{AZURE_CLIENT_ID}",                         # Full URI format
    f"api://{AZURE_CLIENT_ID}/access_as_user",          # With scope
]

# =============================================================================
# CUSTOMER MAPPING
# =============================================================================

CUSTOMER_MAPPING = {
    "users": {
        "kmadhava@ordr.net": "customer-b",
    },
    "tenants": {},
    "customers": {
        "customer-a": {"name": "Healthcare Corp", "data_set": "tenant-a", "enabled": True},
        "customer-b": {"name": "Manufacturing Inc", "data_set": "tenant-b", "enabled": True}
    },
    "default_customer": "customer-a"
}

# =============================================================================
# JWT VALIDATION
# =============================================================================

@lru_cache(maxsize=1)
def get_jwks_client():
    logger.info("Initializing JWKS client...")
    return PyJWKClient(AZURE_JWKS_URL, cache_keys=True, lifespan=3600)


def validate_jwt_token(token: str) -> dict:
    """Validate JWT token - with detailed logging."""
    try:
        # First, decode WITHOUT validation to see what's in the token
        unverified = jwt.decode(token, options={"verify_signature": False})
        
        token_aud = unverified.get("aud", "MISSING")
        token_iss = unverified.get("iss", "MISSING")
        token_email = unverified.get("preferred_username") or unverified.get("email") or unverified.get("upn", "MISSING")
        
        logger.info(f"Token details - aud: {token_aud}, iss: {token_iss}, user: {token_email}")
        
        # Check if audience matches any valid format
        if token_aud not in VALID_AUDIENCES:
            logger.warning(f"Audience mismatch! Token has: {token_aud}")
            logger.warning(f"Valid audiences are: {VALID_AUDIENCES}")
            # Don't fail yet - let's try to validate anyway
        
        # Get signing key
        jwks_client = get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        
        # Try validation with each valid audience
        for valid_aud in VALID_AUDIENCES:
            try:
                payload = jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=["RS256"],
                    audience=valid_aud,
                    options={"verify_exp": True, "verify_aud": True, "verify_iss": False}
                )
                
                # Verify issuer is from Microsoft (accept both v1.0 and v2.0)
                issuer = payload.get("iss", "")
                if not any(issuer.startswith(prefix) for prefix in AZURE_ISSUER_PREFIXES):
                    raise ValueError(f"Invalid issuer: {issuer}")
                
                logger.info(f"✅ Token validated with audience: {valid_aud}")
                return payload
                
            except jwt.InvalidAudienceError:
                continue  # Try next audience
        
        # If we get here, none of the audiences worked
        raise ValueError(f"Invalid audience. Token has: {token_aud}, expected one of: {VALID_AUDIENCES}")
        
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired")
    except Exception as e:
        raise ValueError(f"Token validation failed: {e}")


def get_customer_for_user(user_email: str, tenant_id: str) -> Optional[dict]:
    """Map user/tenant to customer."""
    
    # Check tenant mapping
    if tenant_id in CUSTOMER_MAPPING["tenants"]:
        customer_id = CUSTOMER_MAPPING["tenants"][tenant_id]
        customer = CUSTOMER_MAPPING["customers"].get(customer_id)
        if customer and customer.get("enabled"):
            return {"customer_id": customer_id, **customer}
    
    # Check user mapping (case-insensitive)
    user_email_lower = user_email.lower()
    for email, customer_id in CUSTOMER_MAPPING["users"].items():
        if email.lower() == user_email_lower:
            customer = CUSTOMER_MAPPING["customers"].get(customer_id)
            if customer and customer.get("enabled"):
                return {"customer_id": customer_id, **customer}
    
    # Use default in TEST_MODE
    if TEST_MODE and CUSTOMER_MAPPING.get("default_customer"):
        customer_id = CUSTOMER_MAPPING["default_customer"]
        customer = CUSTOMER_MAPPING["customers"].get(customer_id)
        if customer:
            logger.info(f"Using default customer for {user_email}")
            return {"customer_id": customer_id, **customer}
    
    return None


# =============================================================================
# FASTAPI APP
# =============================================================================

app = FastAPI(title="Ordr Auth Validator")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "healthy", "service": "ordr-auth", "test_mode": TEST_MODE}


@app.get("/auth")
def auth(authorization: Optional[str] = Header(None), response: Response = None):
    """Validate token and return customer info."""
    
    if not authorization:
        logger.warning("No Authorization header")
        raise HTTPException(status_code=401, detail="No Authorization header")
    
    if not authorization.startswith("Bearer "):
        logger.warning("Authorization header not Bearer type")
        raise HTTPException(status_code=401, detail="Expected Bearer token")
    
    token = authorization[7:]
    logger.info(f"Received token (first 50 chars): {token[:50]}...")
    
    # Validate token
    try:
        payload = validate_jwt_token(token)
    except ValueError as e:
        logger.warning(f"Token validation failed: {e}")
        raise HTTPException(status_code=401, detail=str(e))
    
    # Extract user info
    tenant_id = payload.get("tid", "")
    user_email = payload.get("preferred_username") or payload.get("email") or payload.get("upn", "")
    user_name = payload.get("name", "")
    
    logger.info(f"Token valid for: {user_email} (tenant: {tenant_id})")
    
    # Get customer mapping
    customer = get_customer_for_user(user_email, tenant_id)
    
    if not customer:
        logger.warning(f"No customer mapping for {user_email}")
        raise HTTPException(status_code=403, detail="User not authorized")
    
    # Set response headers
    response.headers["X-Customer-Id"] = customer["customer_id"]
    response.headers["X-Customer-Name"] = customer["name"]
    response.headers["X-Data-Set"] = customer["data_set"]
    response.headers["X-User-Email"] = user_email
    response.headers["X-User-Name"] = user_name
    response.headers["X-Tenant-Id"] = tenant_id
    
    logger.info(f"✅ Auth OK: {user_email} → {customer['name']}")
    
    return {"status": "authorized", "customer": customer["name"]}


@app.get("/mappings")
def mappings():
    """Show mappings (TEST_MODE only)."""
    if not TEST_MODE:
        raise HTTPException(status_code=403, detail="Only in TEST_MODE")
    return CUSTOMER_MAPPING


@app.get("/debug-token")
def debug_token(authorization: Optional[str] = Header(None)):
    """Debug endpoint - decode token without validation."""
    if not authorization or not authorization.startswith("Bearer "):
        return {"error": "No Bearer token"}
    
    token = authorization[7:]
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        return {
            "decoded": True,
            "aud": unverified.get("aud"),
            "iss": unverified.get("iss"),
            "sub": unverified.get("sub"),
            "preferred_username": unverified.get("preferred_username"),
            "email": unverified.get("email"),
            "upn": unverified.get("upn"),
            "tid": unverified.get("tid"),
            "exp": unverified.get("exp"),
            "valid_audiences_we_accept": VALID_AUDIENCES
        }
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    import uvicorn
    
    port = int(os.environ.get("PORT", 8080))
    
    logger.info(f"Starting Ordr Auth on port {port}")
    logger.info(f"Azure Client ID: {AZURE_CLIENT_ID}")
    logger.info(f"Valid audiences: {VALID_AUDIENCES}")
    logger.info(f"Valid issuer prefixes: {AZURE_ISSUER_PREFIXES}")
    logger.info(f"Test Mode: {TEST_MODE}")
    
    uvicorn.run(app, host="0.0.0.0", port=port)
