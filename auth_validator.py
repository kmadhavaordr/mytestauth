"""
Ordr Auth Validator Service

Validates Azure AD JWT tokens and maps users to customers.

Endpoints:
- GET /auth    - Validate token, return customer info in headers
- GET /health  - Health check
- GET /mappings - Show user/tenant mappings (TEST_MODE only)

Environment Variables:
- PORT: Port to run on (default: 8080)
- AZURE_CLIENT_ID: Your App Registration Client ID
- TEST_MODE: "true" to allow unmapped users with default customer
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
AZURE_ISSUER_PREFIX = "https://login.microsoftonline.com/"
TEST_MODE = os.environ.get("TEST_MODE", "false").lower() == "true"

# =============================================================================
# CUSTOMER MAPPING - EDIT THIS FOR YOUR USERS/TENANTS
# =============================================================================

CUSTOMER_MAPPING = {
    # =========================================================================
    # USER MAPPING - For testing with single tenant (ORDR)
    # Maps user email → customer_id
    # =========================================================================
    "users": {
        "kmadhava@ordr.net": "customer-a",      # You → Healthcare data
        "mkidambi@ordr.net": "customer-a",      # Add colleagues here
        # "otheruser@ordr.net": "customer-b",   # Uncomment to test customer-b
    },
    
    # =========================================================================
    # TENANT MAPPING - For production multi-tenant
    # Maps Azure tenant ID → customer_id
    # =========================================================================
    "tenants": {
        # Add real customer tenant IDs here:
        # "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx": "customer-contoso",
    },
    
    # =========================================================================
    # CUSTOMER DETAILS
    # =========================================================================
    "customers": {
        "customer-a": {
            "name": "Healthcare Corp",
            "data_set": "tenant-a",
            "enabled": True
        },
        "customer-b": {
            "name": "Manufacturing Inc",
            "data_set": "tenant-b",
            "enabled": True
        }
    },
    
    # Default for unmapped users (only used in TEST_MODE)
    "default_customer": "customer-a"
}

# =============================================================================
# JWT VALIDATION
# =============================================================================

@lru_cache(maxsize=1)
def get_jwks_client():
    """Get cached JWKS client for Microsoft's public keys."""
    logger.info("Initializing JWKS client...")
    return PyJWKClient(AZURE_JWKS_URL, cache_keys=True, lifespan=3600)


def validate_jwt_token(token: str) -> dict:
    """Validate JWT token from Azure AD. Returns claims dict."""
    try:
        jwks_client = get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=AZURE_CLIENT_ID,
            options={"verify_exp": True, "verify_aud": True, "verify_iss": False}
        )
        
        # Verify issuer is from Microsoft
        issuer = payload.get("iss", "")
        if not issuer.startswith(AZURE_ISSUER_PREFIX):
            raise ValueError(f"Invalid issuer: {issuer}")
        
        return payload
        
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired")
    except jwt.InvalidAudienceError:
        raise ValueError(f"Invalid audience (expected {AZURE_CLIENT_ID})")
    except Exception as e:
        raise ValueError(f"Token validation failed: {e}")


def get_customer_for_user(user_email: str, tenant_id: str) -> Optional[dict]:
    """Map user/tenant to customer. Returns customer info or None."""
    
    # 1. Check tenant mapping (production)
    if tenant_id in CUSTOMER_MAPPING["tenants"]:
        customer_id = CUSTOMER_MAPPING["tenants"][tenant_id]
        customer = CUSTOMER_MAPPING["customers"].get(customer_id)
        if customer and customer.get("enabled"):
            return {"customer_id": customer_id, **customer}
    
    # 2. Check user mapping (testing)
    user_email_lower = user_email.lower()
    for email, customer_id in CUSTOMER_MAPPING["users"].items():
        if email.lower() == user_email_lower:
            customer = CUSTOMER_MAPPING["customers"].get(customer_id)
            if customer and customer.get("enabled"):
                return {"customer_id": customer_id, **customer}
    
    # 3. Use default (TEST_MODE only)
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

app = FastAPI(title="Ordr Auth Validator", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# ENDPOINTS
# =============================================================================

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "ordr-auth",
        "test_mode": TEST_MODE,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@app.get("/auth")
def auth(authorization: Optional[str] = Header(None), response: Response = None):
    """
    Validate token and return customer info in headers.
    
    Returns 200 with headers:
    - X-Customer-Id
    - X-Customer-Name
    - X-Data-Set
    - X-User-Email
    - X-Tenant-Id
    
    Returns 401 if token invalid, 403 if user not authorized.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No Bearer token")
    
    token = authorization[7:]
    
    # Validate token
    try:
        payload = validate_jwt_token(token)
    except ValueError as e:
        logger.warning(f"Token validation failed: {e}")
        raise HTTPException(status_code=401, detail=str(e))
    
    # Extract user info
    tenant_id = payload.get("tid", "")
    user_email = payload.get("preferred_username") or payload.get("email") or ""
    user_name = payload.get("name", "")
    
    logger.info(f"Token valid: {user_email} from tenant {tenant_id[:8]}...")
    
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
    
    logger.info(f"Auth OK: {user_email} → {customer['name']}")
    
    return {"status": "authorized", "customer": customer["name"]}


@app.get("/mappings")
def mappings():
    """Show all mappings (TEST_MODE only)."""
    if not TEST_MODE:
        raise HTTPException(status_code=403, detail="Only in TEST_MODE")
    return CUSTOMER_MAPPING


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.environ.get("PORT", 8080))
    
    logger.info(f"Starting Ordr Auth on port {port}")
    logger.info(f"Azure Client ID: {AZURE_CLIENT_ID}")
    logger.info(f"Test Mode: {TEST_MODE}")
    logger.info(f"Mapped users: {list(CUSTOMER_MAPPING['users'].keys())}")
    
    uvicorn.run(app, host="0.0.0.0", port=port)
