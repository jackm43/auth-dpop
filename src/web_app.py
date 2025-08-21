"""
Web application demonstrating Okta authorization code flow with refresh tokens.

This Flask application shows how to:
1. Initiate authorization code flow with PKCE
2. Handle the authorization callback
3. Exchange authorization code for tokens (including refresh token)
4. Use refresh tokens to get new access tokens
5. Make authenticated API calls using DPoP
"""

import os
import secrets
import hashlib
import base64
import json
import logging
from urllib.parse import urlencode, urlparse, parse_qs
from typing import Dict, Any, Optional

from flask import Flask, request, redirect, session, jsonify, render_template_string, render_template
from dotenv import load_dotenv

from okta_service import OktaHelper

load_dotenv()

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

class WebAuthHelper(OktaHelper):
    """
    Extended OktaHelper for web application authorization code flow.
    """
    
    def __init__(self):
        """Initialize with web app configuration."""
        super().__init__()
        self.web_app_client_id = os.getenv("WEB_APP_CLIENT_ID", "0oauicjdbzUbn8n5h697")
        self.redirect_uri = os.getenv("REDIRECT_URI", "http://localhost:8080/callback")
        self.okta_client_id = self.web_app_client_id
    
    def generate_pkce_challenge(self) -> tuple[str, str]:
        """
        Generate PKCE code verifier and challenge.
        
        Returns:
            tuple: (code_verifier, code_challenge)
        """
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        return code_verifier, code_challenge
    
    def get_authorization_url(self, state: str, code_challenge: str) -> str:
        """
        Build authorization URL for OAuth2 authorization code flow.
        
        Args:
            state: Random state parameter for CSRF protection
            code_challenge: PKCE code challenge
            
        Returns:
            str: Complete authorization URL
        """
        params = {
            'client_id': self.web_app_client_id,
            'response_type': 'code',
            'scope': 'app.read app.write refresh openid profile',
            'redirect_uri': self.redirect_uri,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        auth_url = f"{self.get_issuer()}/v1/authorize"
        return f"{auth_url}?{urlencode(params)}"
    
    def exchange_code_for_tokens(self, code: str, code_verifier: str) -> Optional[Dict[str, Any]]:
        """
        Exchange authorization code for access and refresh tokens.
        
        Args:
            code: Authorization code from callback
            code_verifier: PKCE code verifier
            
        Returns:
            Dict containing tokens if successful, None otherwise
        """
        try:
            cc_token = self.generate_cc_token()
            
            dpop_token = self.generate_dpop_token('POST', self.get_token_endpoint())
            
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
                'DPoP': dpop_token
            }
            
            data = {
                'grant_type': 'authorization_code',
                'client_id': self.web_app_client_id,
                'code': code,
                'redirect_uri': self.redirect_uri,
                'code_verifier': code_verifier,
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion': cc_token
            }
            
            import requests
            response = requests.post(self.get_token_endpoint(), headers=headers, data=data)
            
            logging.debug(f"Token exchange response status: {response.status_code}")
            logging.debug(f"Token exchange response: {response.text}")
            
            if response.status_code == 200:
                return response.json()
            else:
                logging.error(f"Token exchange failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as error:
            logging.error(f"Error exchanging code for tokens: {error}")
            return None

web_helper = WebAuthHelper()

@app.route('/')
def index():
    """Home page with login link."""
    return render_template('index.html', session=session)

@app.route('/login')
def login():
    """Initiate OAuth2 authorization code flow."""
    code_verifier, code_challenge = web_helper.generate_pkce_challenge()
    state = secrets.token_urlsafe(32)
    
    session['code_verifier'] = code_verifier
    session['state'] = state
    
    auth_url = web_helper.get_authorization_url(state, code_challenge)
    
    logging.info(f"Redirecting to authorization URL: {auth_url}")
    return redirect(auth_url)

@app.route('/callback')
def callback():
    """Handle OAuth2 authorization callback."""
    try:
        code = request.args.get('code')
        state = request.args.get('state')
        error = request.args.get('error')
        
        if error:
            return f"Authorization error: {error}", 400
        
        if not code or not state:
            return "Missing code or state parameter", 400
        
        if state != session.get('state'):
            return "Invalid state parameter", 400
        
        code_verifier = session.get('code_verifier')
        if not code_verifier:
            return "Missing code verifier in session", 400
        
        tokens = web_helper.exchange_code_for_tokens(code, code_verifier)
        
        if not tokens:
            return "Failed to exchange code for tokens", 400
        
        session['access_token'] = tokens.get('access_token')
        session['refresh_token'] = tokens.get('refresh_token')
        session['id_token'] = tokens.get('id_token')
        session['expires_in'] = tokens.get('expires_in')
        
        session.pop('code_verifier', None)
        session.pop('state', None)
        
        logging.info("Successfully exchanged code for tokens")
        logging.info(f"Refresh token present: {'refresh_token' in tokens}")
        
        return redirect('/')
        
    except Exception as error:
        logging.error(f"Error in callback: {error}")
        return f"Callback error: {error}", 500

@app.route('/refresh')
def refresh():
    refresh_token = session.get('refresh_token')
    if not refresh_token:
        return "No refresh token available", 400
    
    try:
        web_helper.access_token = session.get('access_token', '')
        web_helper.refresh_token = refresh_token
        
        dpop_token = web_helper.generate_dpop_token('POST', web_helper.get_token_endpoint())
        
        response = web_helper.refresh_token_request(refresh_token, dpop_token)
        
        if response.status_code == 200:
            tokens = response.json()
            
            session['access_token'] = tokens.get('access_token')
            if 'refresh_token' in tokens:
                session['refresh_token'] = tokens['refresh_token']
            
            return jsonify({
                'success': True,
                'message': 'Tokens refreshed successfully',
                'new_access_token': tokens.get('access_token', '')[:50] + '...',
                'refresh_token_rotated': 'refresh_token' in tokens
            })
        else:
            return jsonify({
                'success': False,
                'error': response.text
            }), response.status_code
            
    except Exception as error:
        logging.error(f"Error refreshing token: {error}")
        return jsonify({'success': False, 'error': str(error)}), 500

@app.route('/api-test')
def api_test():
    access_token = session.get('access_token')
    if not access_token:
        return "No access token available", 401
    
    try:
        web_helper.access_token = access_token
        
        from okta_service import OktaService
        service = OktaService()
        service.helper.access_token = access_token
    
        response = service.management_api_call("/api/v1/users", "GET")
        
        if response.status_code == 200:
            users = response.json()
            return jsonify({
                'success': True,
                'message': f'API call successful! Found {len(users)} users.',
                'users_count': len(users)
            })
        else:
            return jsonify({
                'success': False,
                'error': f'API call failed: {response.status_code} - {response.text}'
            }), response.status_code
            
    except Exception as error:
        logging.error(f"Error making API call: {error}")
        return jsonify({'success': False, 'error': str(error)}), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    logging.info("Starting web application on http://localhost:8080")
    logging.info(f"Web App Client ID: {web_helper.web_app_client_id}")
    logging.info(f"Redirect URI: {web_helper.redirect_uri}")
    logging.info(f"Authorization Server: {web_helper.get_issuer()}")
    
    app.run(host='localhost', port=8080, debug=True)
