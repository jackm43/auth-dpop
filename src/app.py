"""
Main application demonstrating Okta DPoP authentication.

This script shows how to authenticate with Okta using DPoP tokens
and make authenticated API calls to retrieve user information.
"""

import json
from okta_service import okta_service
import os
import logging


def main():
    """
    Main function demonstrating Okta DPoP authentication and API usage.
    
    This demonstrates a two-app flow:
    1. First app: Authenticates with custom auth server and gets custom claims
    2. Second app: Uses management API token to access Okta resources
    """
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

    
    # Authenticate with custom authorization server (gets app.read, app.write scopes)
    custom_token = okta_service.authenticate()
    
    if not custom_token:
        logging.error("Failed to authenticate with custom auth server")
        return
    
    # Verify the custom token (JWT from custom issuer)
    try:
        custom_claims = okta_service.verify_token(custom_token, audience=os.getenv("OKTA_AUDIENCE"))
        logging.info("First App - Custom token claims: %s", json.dumps(custom_claims, indent=2))
        
        # Grant a claim for the second app (simulate claim granting)
        granted_claim = {
            "granted_by": custom_claims.get("sub"),
            "granted_scopes": custom_claims.get("scp", []),
            "granted_at": custom_claims.get("iat"),
            "management_access": True
        }
        logging.info("First App - Granted claim for second app: %s", json.dumps(granted_claim, indent=2))
        
    except Exception as err:
        logging.error("Token verification failed: %s", err, exc_info=True)
        return

    # === SECOND APP: Management API Access ===
    logging.info("=== SECOND APP: Management API Access ===")
    
    # Create a second service instance configured for management API
    from okta_service import OktaService
    mgmt_service = OktaService()
    
    # Configure for org authorization server (management API)
    mgmt_service.helper.okta_issuer = ""  # Use org issuer for management API
    mgmt_service.helper.okta_scopes = "okta.users.read"  # Management API scope
    mgmt_service.helper.access_token = ""  # Clear cached token
    mgmt_service.helper.token_cache_file = "assets/mgmt_token_cache.json"
    
    # Authenticate with org authorization server for management API access
    mgmt_token = mgmt_service.authenticate()
    
    if not mgmt_token:
        logging.error("Second App - Failed to authenticate with management API")
        return
    
    logging.info("Second App - Successfully obtained management API token")
    
    # Try to verify management token (might be opaque)
    try:
        mgmt_claims = mgmt_service.verify_token(mgmt_token)
        logging.info("Second App - Management token claims: %s", json.dumps(mgmt_claims, indent=2))
    except Exception as err:
        logging.debug("Management token verification failed (expected for opaque tokens): %s", err)
    
    # Make an authenticated API call to get users using management API token
    users_resp = mgmt_service.management_api_call("/api/v1/users", "GET")
    
    if users_resp.status_code == 200:
        resp_body = users_resp.json()
        logging.info("Second App - Successfully retrieved users from Management API")
        logging.info("Second App - Users count: %d", len(resp_body))
        if resp_body:
            logging.info("Second App - First user: %s", json.dumps(resp_body[0], indent=2))
    else:
        logging.error("Second App - Management API error: %s", users_resp.status_code)
        logging.error("Second App - Response: %s", users_resp.text)
        
    # Demonstrate the claim granting relationship
    logging.info("=== CLAIM GRANTING SUMMARY ===")
    logging.info("First app (custom auth) granted access to second app (management API)")
    logging.info("Granted claim: %s", json.dumps(granted_claim, indent=2))


if __name__ == "__main__":
    main()
