"""
Test script for refresh token functionality.

This script demonstrates the refresh token implementation by:
1. Getting an initial access token
2. Simulating token expiration
3. Using refresh token to get a new access token
4. Testing token revocation
"""

import os
import time
import json
import logging
from okta_service import OktaService

def test_refresh_tokens():
    """
    Test the refresh token functionality.
    """
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    
    # Create service instance
    service = OktaService()
    
    logging.info("=== Testing Refresh Token Functionality ===")
    
    # Step 1: Get initial access token
    logging.info("Step 1: Getting initial access token...")
    token1 = service.authenticate()
    if not token1:
        logging.error("Failed to get initial access token")
        return False
    
    logging.info("Successfully obtained initial access token")
    
    # Check if we got a refresh token
    refresh_token = service.helper._get_cached_refresh_token()
    if refresh_token:
        logging.info("Refresh token is available")
    else:
        logging.warning("No refresh token received - this is expected for client_credentials flow")
        logging.info("Refresh tokens are typically only available with authorization_code flow")
        return True
    
    # Step 2: Simulate token expiration by manipulating cache
    logging.info("Step 2: Simulating token expiration...")
    cache_file = service.helper.token_cache_file
    if os.path.exists(cache_file):
        with open(cache_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Set expiration time to past
        data['expires_at'] = int(time.time()) - 100
        
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        
        logging.info("Token cache modified to simulate expiration")
    
    # Step 3: Try to authenticate again - should use refresh token
    logging.info("Step 3: Attempting to authenticate with expired token...")
    service.helper.access_token = ""  # Clear in-memory token
    
    token2 = service.authenticate()
    if not token2:
        logging.error("Failed to refresh access token")
        return False
    
    if token1 != token2:
        logging.info("Successfully refreshed access token (tokens are different)")
    else:
        logging.info("Token refresh returned same token")
    
    # Step 4: Test token revocation
    logging.info("Step 4: Testing token revocation...")
    revoke_success = service.revoke_refresh_token()
    if revoke_success:
        logging.info("Successfully revoked refresh token")
    else:
        logging.warning("Token revocation failed or not supported")
    
    # Step 5: Test clear tokens
    logging.info("Step 5: Testing token clearing...")
    service.clear_tokens()
    logging.info("Tokens cleared successfully")
    
    # Step 6: Verify we can get a new token after clearing
    logging.info("Step 6: Getting new token after clearing...")
    token3 = service.authenticate()
    if not token3:
        logging.error("Failed to get new token after clearing")
        return False
    
    logging.info("Successfully obtained new token after clearing")
    logging.info("=== Refresh Token Test Complete ===")
    return True

if __name__ == "__main__":
    success = test_refresh_tokens()
    if success:
        logging.info("All refresh token tests passed!")
    else:
        logging.error("Some refresh token tests failed!")
