"""
Okta DPoP (Demonstrating Proof of Possession) Service

This module provides functionality for authenticating with Okta using DPoP tokens
and making authenticated API calls to Okta's management API.
"""

import os
import json
import hashlib
import base64
import time
from pathlib import Path
from typing import Dict, Any, Optional

import jwt
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class OktaHelper:
    """
    Helper class for Okta DPoP authentication and token management.
    
    Provides methods for generating client credentials tokens, DPoP proofs,
    and handling authentication with Okta's OAuth2 token endpoint.
    """
    
    def __init__(self):
        """Initialize Okta helper with configuration and key files."""
        self.okta_domain = "https://integrator-3111559.okta.com"
        self.okta_client_id = "0oauhxpvobW6dZ0qO697"
        self.okta_scopes = "okta.users.read"
        self.cc_private_key_file = "assets/cc_private_key.pem"
        self.dpop_private_key_file = "assets/dpop_private_key.pem"
        self.dpop_public_key_file = "assets/dpop_public_key.json"
        self.access_token = ""
        
        # Load private keys
        self._cc_private_key = None
        self._dpop_private_key = None
        self._dpop_public_key = None
    
    def get_token_endpoint(self) -> str:
        """Get the Okta OAuth2 token endpoint URL."""
        return f"{self.okta_domain}/oauth2/v1/token"
    
    def get_new_jti(self) -> str:
        """Generate a new JWT ID (jti) for token uniqueness."""
        import secrets
        return secrets.token_hex(32)
    
    def _load_cc_private_key(self) -> str:
        """Load the client credentials private key."""
        if self._cc_private_key is None:
            with open(self.cc_private_key_file, 'r') as f:
                self._cc_private_key = f.read()
        return self._cc_private_key
    
    def _load_dpop_private_key(self) -> str:
        """Load the DPoP private key."""
        if self._dpop_private_key is None:
            with open(self.dpop_private_key_file, 'r') as f:
                self._dpop_private_key = f.read()
        return self._dpop_private_key
    
    def _load_dpop_public_key(self) -> Dict[str, Any]:
        """Load the DPoP public key JWK."""
        if self._dpop_public_key is None:
            with open(self.dpop_public_key_file, 'r') as f:
                self._dpop_public_key = json.load(f)['keys'][0]
        return self._dpop_public_key
    
    def generate_cc_token(self) -> str:
        """
        Create a client_credentials assertion (JWT) signed with the private key.
        
        Used to prove the client's identity to Okta's token endpoint.
        
        Returns:
            str: The signed JWT token
        """
        private_key = self._load_cc_private_key()
        with open("assets/cc_public_key.json", 'r') as f:
            cc_jwk = json.load(f)['keys'][0]
        
        now = int(time.time())
        payload = {
            'jti': self.get_new_jti(),
            'iat': now,
            'exp': now + 300,  # 5 minutes
            'aud': self.get_token_endpoint(),
            'iss': self.okta_client_id,
            'sub': self.okta_client_id
        }
        
        headers = {
            'kid': cc_jwk['kid'],
            'alg': 'RS256',
            'typ': 'JWT'
        }
        
        return jwt.encode(payload, private_key, algorithm='RS256', headers=headers)
    
    def generate_dpop_token(self, htm: str, htu: str, additional_claims: Optional[Dict[str, Any]] = None) -> str:
        """
        Create a DPoP proof JWT binding the request to a key pair.
        
        Ensures access token cannot be replayed from another client or endpoint.
        
        Args:
            htm: HTTP method (e.g., 'GET', 'POST')
            htu: HTTP target URI
            additional_claims: Additional claims to include in the DPoP token
            
        Returns:
            str: The signed DPoP JWT token
        """
        private_key = self._load_dpop_private_key()
        public_key = self._load_dpop_public_key()
        
        now = int(time.time())
        payload = {
            'htm': htm,
            'htu': htu,
            'iat': now,
            'jti': self.get_new_jti(),
            'exp': now + 300  # 5 minutes
        }
        
        if additional_claims:
            payload.update(additional_claims)
        
        headers = {
            'typ': 'dpop+jwt',
            'alg': 'RS256',
            'jwk': public_key
        }
        
        return jwt.encode(payload, private_key, algorithm='RS256', headers=headers)
    
    def generate_ath(self, token: str) -> str:
        """
        Generate the access token hash (ath) for DPoP binding.
        
        Args:
            token: The access token to hash
            
        Returns:
            str: Base64URL encoded SHA-256 hash of the token
        """
        token_hash = hashlib.sha256(token.encode('utf-8')).digest()
        ath = base64.urlsafe_b64encode(token_hash).decode('utf-8').rstrip('=')
        return ath
    
    def token_request(self, cc_token: str, dpop_token: str) -> requests.Response:
        """
        Generate token request using client_credentials grant type.
        
        Args:
            cc_token: Client credentials JWT token
            dpop_token: DPoP proof token
            
        Returns:
            requests.Response: The HTTP response from the token endpoint
        """
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
            'DPoP': dpop_token
        }
        
        data = {
            'grant_type': 'client_credentials',
            'scope': self.okta_scopes,
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': cc_token
        }
        
        return requests.post(self.get_token_endpoint(), headers=headers, data=data)


class OktaService:
    """
    Main service class for Okta DPoP authentication and API calls.
    
    Provides high-level methods for authenticating with Okta and making
    authenticated requests to the Okta Management API.
    """
    
    def __init__(self):
        """Initialize the Okta service with a helper instance."""
        self.helper = OktaHelper()
    
    def authenticate(self) -> Optional[str]:
        """
        Authenticate and generate access token.
        
        Returns:
            str: The access token if successful, None otherwise
        """
        if not self.helper.access_token:
            print("Valid access token not found. Retrieving new token...\n")
            try:
                cc_token = self.helper.generate_cc_token()
                dpop_token = self.helper.generate_dpop_token('POST', self.helper.get_token_endpoint())
                token_resp = self.helper.token_request(cc_token, dpop_token)
                resp_body = token_resp.json()
                
                print(f"Token response status: {token_resp.status_code}")
                print(f"Token response body: {resp_body}")
                print(f"Token response headers: {dict(token_resp.headers)}")
                
                # Check for DPoP nonce error
                if 'dpop-nonce' in token_resp.headers:
                    dpop_nonce = token_resp.headers['dpop-nonce']
                    print(f"Token call failed with nonce error\n")
                    dpop_token = self.helper.generate_dpop_token(
                        'POST', 
                        self.helper.get_token_endpoint(), 
                        {'nonce': dpop_nonce}
                    )
                    cc_token = self.helper.generate_cc_token()
                    print(f"Retrying token call to {self.helper.get_token_endpoint()} with DPoP nonce {dpop_nonce}")
                    token_resp = self.helper.token_request(cc_token, dpop_token)
                    resp_body = token_resp.json()
                
                self.helper.access_token = resp_body["access_token"]
                print("Successfully retrieved access token\n")
                
            except Exception as error:
                print(f"Error in authentication: {error}\n")
                import traceback
                traceback.print_exc()
                return None
        
        return self.helper.access_token
    
    def management_api_call(self, relative_uri: str, http_method: str, 
                          headers: Optional[Dict[str, str]] = None, 
                          body: Optional[str] = None) -> requests.Response:
        """
        Construct Okta management API calls with DPoP authentication.
        
        Args:
            relative_uri: The relative URI path for the API call
            http_method: HTTP method (GET, POST, PUT, DELETE, etc.)
            headers: Additional headers to include
            body: Request body for POST/PUT requests
            
        Returns:
            requests.Response: The HTTP response from the API call
        """
        uri = f"{self.helper.okta_domain}{relative_uri}"
        ath = self.helper.generate_ath(self.helper.access_token)
        dpop_token = self.helper.generate_dpop_token(http_method, uri, {'ath': ath})
        
        req_headers = {
            'Accept': 'application/json',
            'Authorization': f'DPoP {self.helper.access_token}',
            'DPoP': dpop_token
        }
        
        if headers:
            req_headers.update(headers)
        
        return requests.request(http_method, uri, headers=req_headers, data=body)


# Create singleton instances
okta_helper = OktaHelper()
okta_service = OktaService()
