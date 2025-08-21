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
from jwt import PyJWKClient
import requests
from dotenv import load_dotenv
import logging

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
        self.okta_domain = os.getenv("OKTA_DOMAIN", "https://integrator-3111559.okta.com")
        self.okta_issuer = os.getenv("OKTA_ISSUER", "")
        self.okta_client_id = os.getenv("OKTA_CLIENT_ID", "0oauhxpvobW6dZ0qO697")
        self.okta_scopes = os.getenv("OKTA_SCOPES", "okta.users.read")
        self.cc_private_key_file = os.getenv("OKTA_CC_PRIVATE_KEY_FILE", "assets/cc_private_key.pem")
        self.dpop_private_key_file = os.getenv("OKTA_DPOP_PRIVATE_KEY_FILE", "assets/dpop_private_key.pem")
        self.dpop_public_key_file = os.getenv("OKTA_DPOP_PUBLIC_KEY_FILE", "assets/dpop_public_key.json")
        self.token_cache_file = os.getenv("OKTA_TOKEN_CACHE_FILE", "assets/token_cache.json")
        self.access_token = ""
        self.refresh_token = ""
        
        # Load private keys
        self._cc_private_key = None
        self._dpop_private_key = None
        self._dpop_public_key = None
    
    def get_token_endpoint(self) -> str:
        """Get the Okta OAuth2 token endpoint URL."""
        if self.okta_issuer:
            return f"{self.okta_issuer}/v1/token"
        return f"{self.okta_domain}/oauth2/v1/token"

    def get_issuer(self) -> str:
        """Return the issuer URL used for token verification."""
        if self.okta_issuer:
            return self.okta_issuer
        # Org issuer is used for Okta Management API tokens
        return f"{self.okta_domain}/oauth2"
    
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

    def _get_dpop_kid(self) -> str:
        """Return the DPoP public key kid for token binding identity."""
        pub = self._load_dpop_public_key()
        return pub.get('kid', '')

    def _read_cached_token(self) -> Optional[str]:
        """Read a cached access token if it matches current config and is not expired."""
        try:
            if not os.path.exists(self.token_cache_file):
                return None
            with open(self.token_cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            required = {
                'issuer': self.get_issuer(),
                'client_id': self.okta_client_id,
                'scopes': self.okta_scopes,
                'dpop_kid': self._get_dpop_kid()
            }
            for k, v in required.items():
                if data.get(k) != v:
                    return None
            now = int(time.time())
            if int(data.get('expires_at', 0)) > now + 30:
                # Also cache the refresh token if available
                if data.get('refresh_token'):
                    self.refresh_token = data.get('refresh_token')
                return data.get('access_token')
            return None
        except Exception:
            return None

    def _write_cached_token(self, access_token: str, expires_in: Optional[int], refresh_token: Optional[str] = None) -> None:
        """Persist the access token with config tuple and computed expiry."""
        try:
            now = int(time.time())
            expires_at = now + int(expires_in or 300)
            payload = {
                'issuer': self.get_issuer(),
                'client_id': self.okta_client_id,
                'scopes': self.okta_scopes,
                'dpop_kid': self._get_dpop_kid(),
                'access_token': access_token,
                'expires_at': expires_at
            }
            if refresh_token:
                payload['refresh_token'] = refresh_token
            os.makedirs(os.path.dirname(self.token_cache_file), exist_ok=True)
            with open(self.token_cache_file, 'w', encoding='utf-8') as f:
                json.dump(payload, f)
        except Exception:
            # Best-effort cache; ignore write failures
            pass
    
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

    def verify_access_token(self, token: str, audience: Optional[str] = None) -> Dict[str, Any]:
        """
        Verify a JWT access token against the issuer JWKS.

        Args:
            token: The JWT access token to verify
            audience: Expected audience to validate (optional)

        Returns:
            Dict[str, Any]: Decoded token claims if verification succeeds
        """
        issuer = self.get_issuer()
        jwks_uri = f"{issuer}/v1/keys"
        jwk_client = PyJWKClient(jwks_uri)
        signing_key = jwk_client.get_signing_key_from_jwt(token)

        options: Dict[str, Any] = {}
        if not audience:
            options["verify_aud"] = False

        return jwt.decode(
            token,
            key=signing_key.key,
            algorithms=['RS256'],
            issuer=issuer,
            audience=audience,
            options=options if options else None
        )
    
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

    def refresh_token_request(self, refresh_token: str, dpop_token: str) -> requests.Response:
        """
        Generate token request using refresh_token grant type.
        
        Args:
            refresh_token: The refresh token to exchange
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
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'scope': self.okta_scopes
        }
        
        return requests.post(self.get_token_endpoint(), headers=headers, data=data)

    def revoke_token_request(self, token: str, token_type_hint: str = "refresh_token") -> requests.Response:
        """
        Revoke a token (access or refresh token).
        
        Args:
            token: The token to revoke
            token_type_hint: Hint about the token type ("access_token" or "refresh_token")
            
        Returns:
            requests.Response: The HTTP response from the revoke endpoint
        """
        revoke_endpoint = f"{self.get_token_endpoint().replace('/token', '/revoke')}"
        
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        data = {
            'token': token,
            'token_type_hint': token_type_hint,
            'client_id': self.okta_client_id
        }
        
        return requests.post(revoke_endpoint, headers=headers, data=data)

    def _is_token_expired(self) -> bool:
        """
        Check if the current cached token is expired.
        
        Returns:
            bool: True if token is expired or about to expire, False otherwise
        """
        try:
            if not os.path.exists(self.token_cache_file):
                return True
            with open(self.token_cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            now = int(time.time())
            # Consider token expired if it expires within 30 seconds
            return int(data.get('expires_at', 0)) <= now + 30
        except Exception:
            return True

    def _get_cached_refresh_token(self) -> Optional[str]:
        """
        Get the cached refresh token if available and configuration matches.
        
        Returns:
            str: The refresh token if available, None otherwise
        """
        try:
            if not os.path.exists(self.token_cache_file):
                return None
            with open(self.token_cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            required = {
                'issuer': self.get_issuer(),
                'client_id': self.okta_client_id,
                'scopes': self.okta_scopes,
                'dpop_kid': self._get_dpop_kid()
            }
            for k, v in required.items():
                if data.get(k) != v:
                    return None
            return data.get('refresh_token')
        except Exception:
            return None


class OktaService:
    """
    Main service class for Okta DPoP authentication and API calls.
    
    Provides high-level methods for authenticating with Okta and making
    authenticated requests to the Okta Management API.
    """
    
    def __init__(self):
        """Initialize the Okta service with a helper instance."""
        self.helper = OktaHelper()
        logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    
    def authenticate(self) -> Optional[str]:
        """
        Authenticate and generate access token with refresh token support.u
        
        Returns:
            str: The access token if successful, None otherwise
        """
        if not self.helper.access_token or self.helper._is_token_expired():
            # First, try to reuse cached token if not expired
            if not self.helper._is_token_expired():
                cached = self.helper._read_cached_token()
                if cached:
                    self.helper.access_token = cached
                    return self.helper.access_token
            
            # If token is expired, try to refresh using refresh token
            refresh_token = self.helper._get_cached_refresh_token()
            if refresh_token:
                logging.info("Access token expired. Attempting to refresh using refresh token...")
                try:
                    new_token = self._refresh_access_token(refresh_token)
                    if new_token:
                        return new_token
                    logging.warning("Refresh token failed or expired, falling back to client credentials")
                except Exception as error:
                    logging.warning(f"Error refreshing token: {error}, falling back to client credentials")
            
            # Fall back to client credentials flow
            logging.info("Retrieving new token using client credentials...")
            try:
                return self._get_new_access_token()
                
            except Exception as error:
                logging.exception(f"Error in authentication: {error}")
                import traceback
                traceback.print_exc()
                return None
        
        return self.helper.access_token

    def _refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """
        Refresh the access token using a refresh token.
        
        Args:
            refresh_token: The refresh token to use
            
        Returns:
            str: The new access token if successful, None otherwise
        """
        try:
            dpop_token = self.helper.generate_dpop_token('POST', self.helper.get_token_endpoint())
            token_resp = self.helper.refresh_token_request(refresh_token, dpop_token)
            resp_body = token_resp.json()
            
            logging.debug(f"Refresh token response status: {token_resp.status_code}")
            logging.debug(f"Refresh token response body: {resp_body}")
            logging.debug(f"Refresh token response headers: {dict(token_resp.headers)}")
            
            if token_resp.status_code != 200:
                logging.error(f"Refresh token request failed: {resp_body}")
                return None
            
            # Check for DPoP nonce error
            if 'dpop-nonce' in token_resp.headers:
                dpop_nonce = token_resp.headers['dpop-nonce']
                dpop_token = self.helper.generate_dpop_token(
                    'POST', 
                    self.helper.get_token_endpoint(), 
                    {'nonce': dpop_nonce}
                )
                logging.info(f"Retrying refresh token call to {self.helper.get_token_endpoint()} with DPoP nonce {dpop_nonce}")
                token_resp = self.helper.refresh_token_request(refresh_token, dpop_token)
                resp_body = token_resp.json()
                
                if token_resp.status_code != 200:
                    logging.error(f"Refresh token retry failed: {resp_body}")
                    return None
            
            self.helper.access_token = resp_body["access_token"]
            new_refresh_token = resp_body.get("refresh_token", refresh_token)  # Use new refresh token if provided
            self.helper.refresh_token = new_refresh_token
            
            self.helper._write_cached_token(
                access_token=self.helper.access_token,
                expires_in=resp_body.get("expires_in"),
                refresh_token=new_refresh_token
            )
            logging.info("Successfully refreshed access token")
            return self.helper.access_token
            
        except Exception as error:
            logging.error(f"Error refreshing token: {error}")
            return None

    def _get_new_access_token(self) -> Optional[str]:
        """
        Get a new access token using client credentials flow.
        
        Returns:
            str: The new access token if successful, None otherwise
        """
        cc_token = self.helper.generate_cc_token()
        dpop_token = self.helper.generate_dpop_token('POST', self.helper.get_token_endpoint())
        token_resp = self.helper.token_request(cc_token, dpop_token)
        resp_body = token_resp.json()
        
        logging.debug(f"Token response status: {token_resp.status_code}")
        logging.debug(f"Token response body: {resp_body}")
        logging.debug(f"Token response headers: {dict(token_resp.headers)}")
        
        if token_resp.status_code != 200:
            logging.error(f"Token request failed: {resp_body}")
            return None
        
        # Check for DPoP nonce error
        if 'dpop-nonce' in token_resp.headers:
            dpop_nonce = token_resp.headers['dpop-nonce']
            logging.info("Token call failed with nonce error; retrying with nonce")
            dpop_token = self.helper.generate_dpop_token(
                'POST', 
                self.helper.get_token_endpoint(), 
                {'nonce': dpop_nonce}
            )
            cc_token = self.helper.generate_cc_token()
            logging.info(f"Retrying token call to {self.helper.get_token_endpoint()} with DPoP nonce {dpop_nonce}")
            token_resp = self.helper.token_request(cc_token, dpop_token)
            resp_body = token_resp.json()
            
            if token_resp.status_code != 200:
                logging.error(f"Token retry failed: {resp_body}")
                return None
        
        self.helper.access_token = resp_body["access_token"]
        refresh_token = resp_body.get("refresh_token")  # May or may not be present
        if refresh_token:
            self.helper.refresh_token = refresh_token
        
        self.helper._write_cached_token(
            access_token=self.helper.access_token,
            expires_in=resp_body.get("expires_in"),
            refresh_token=refresh_token
        )
        logging.info("Successfully retrieved access token")
        return self.helper.access_token
    
    def management_api_call(self, relative_uri: str, http_method: str, 
                          headers: Optional[Dict[str, str]] = None, 
                          body: Optional[str] = None, use_dpop: bool = None) -> requests.Response:
        """
        Construct Okta management API calls with appropriate authentication.
        
        Args:
            relative_uri: The relative URI path for the API call
            http_method: HTTP method (GET, POST, PUT, DELETE, etc.)
            headers: Additional headers to include
            body: Request body for POST/PUT requests
            use_dpop: Whether to use DPoP authentication. If None, auto-detects based on issuer
            
        Returns:
            requests.Response: The HTTP response from the API call
        """

        token = self.authenticate()
        if not token:
            raise Exception("Failed to obtain valid access token for API call")
        
        uri = f"{self.helper.okta_domain}{relative_uri}"
        
        if use_dpop is None:
            # Custom authorization servers require DPoP, org authorization server uses Bearer
            use_dpop = bool(self.helper.okta_issuer)
        
        if use_dpop:
            ath = self.helper.generate_ath(self.helper.access_token)
            dpop_token = self.helper.generate_dpop_token(http_method, uri, {'ath': ath})
            req_headers = {
                'Accept': 'application/json',
                'Authorization': f'DPoP {self.helper.access_token}',
                'DPoP': dpop_token
            }
        else:
            # Use Bearer authentication (for org authorization server / Management API)
            req_headers = {
                'Accept': 'application/json',
                'Authorization': f'Bearer {self.helper.access_token}',
                'Content-Type': 'application/json'
            }
        
        if headers:
            req_headers.update(headers)
        
        return requests.request(http_method, uri, headers=req_headers, data=body)

    def verify_token(self, token: str, audience: Optional[str] = None) -> Dict[str, Any]:
        """Verify a JWT access token and return its claims."""
        return self.helper.verify_access_token(token, audience)

    def revoke_refresh_token(self) -> bool:
        """
        Revoke the current refresh token and clear cached tokens.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            refresh_token = self.helper._get_cached_refresh_token()
            if not refresh_token:
                logging.warning("No refresh token available to revoke")
                return False
            
            response = self.helper.revoke_token_request(refresh_token, "refresh_token")
            
            if response.status_code == 200:
                # Clear cached tokens
                self.helper.access_token = ""
                self.helper.refresh_token = ""
                if os.path.exists(self.helper.token_cache_file):
                    os.remove(self.helper.token_cache_file)
                logging.info("Successfully revoked refresh token and cleared cache")
                return True
            else:
                logging.error(f"Failed to revoke refresh token: {response.status_code} - {response.text}")
                return False
                
        except Exception as error:
            logging.error(f"Error revoking refresh token: {error}")
            return False

    def clear_tokens(self) -> None:
        """
        Clear all cached tokens without revoking them.
        """
        self.helper.access_token = ""
        self.helper.refresh_token = ""
        if os.path.exists(self.helper.token_cache_file):
            os.remove(self.helper.token_cache_file)
        logging.info("Cleared all cached tokens")

okta_helper = OktaHelper()
okta_service = OktaService()
