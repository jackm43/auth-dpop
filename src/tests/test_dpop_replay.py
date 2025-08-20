"""
Tests for DPoP non-replayability and binding functionality.

These tests verify that DPoP tokens are properly bound to specific requests
and cannot be replayed or used for different endpoints/methods.
"""

import json
import time
from pathlib import Path

import jwt
import pytest
import requests

from okta_service import okta_service, okta_helper


# Test constants
USERS_EP = "/api/v1/users"
GROUPS_EP = "/api/v1/groups"


def make_dpop(htm: str, htu: str, extra: dict = None) -> str:
    """
    Create a DPoP token for testing purposes.
    
    Args:
        htm: HTTP method
        htu: HTTP target URI
        extra: Additional claims to include
        
    Returns:
        str: The signed DPoP JWT token
    """
    if extra is None:
        extra = {}
    
    priv = okta_helper._load_dpop_private_key()
    pub = okta_helper._load_dpop_public_key()
    
    payload = {
        'htm': htm,
        'htu': htu,
        'iat': int(time.time()),
        'jti': okta_helper.get_new_jti(),
        **extra
    }
    
    headers = {
        'typ': 'dpop+jwt',
        'alg': 'RS256',
        'jwk': pub
    }
    
    return jwt.encode(payload, priv, algorithm='RS256', headers=headers)


def call_mgmt(relative_uri: str, method: str, headers: dict = None, body: str = None) -> requests.Response:
    """
    Make a management API call for testing.
    
    Args:
        relative_uri: The relative URI path
        method: HTTP method
        headers: Request headers
        body: Request body
        
    Returns:
        requests.Response: The HTTP response
    """
    if headers is None:
        headers = {}
    
    url = f"{okta_helper.okta_domain}{relative_uri}"
    return requests.request(method, url, headers=headers, data=body)


class TestDPoPNonReplayability:
    """Test class for DPoP non-replayability and binding functionality."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test environment and authenticate."""
        self.access_token = okta_service.authenticate()
        assert isinstance(self.access_token, str)
    
    def test_dpop_required_missing_dpop_header_fails(self):
        """Test that requests without DPoP header fail."""
        res = call_mgmt(USERS_EP, "GET", {
            'Accept': 'application/json',
            'Authorization': f'DPoP {self.access_token}'
        })
        
        assert res.status_code >= 400
        assert res.status_code < 500  # typically 401
    
    def test_happy_path_fresh_dpop_proof_with_correct_ath_succeeds(self):
        """Test that fresh DPoP proof with correct ath succeeds."""
        uri = f"{okta_helper.okta_domain}{USERS_EP}"
        ath = okta_helper.generate_ath(self.access_token)
        dpop = make_dpop("GET", uri, {'ath': ath})
        
        # Okta may require a nonce on first try
        res = call_mgmt(USERS_EP, "GET", {
            'Accept': 'application/json',
            'Authorization': f'DPoP {self.access_token}',
            'DPoP': dpop
        })
        
        if res.status_code == 400 and 'dpop-nonce' in res.headers:
            nonce = res.headers['dpop-nonce']
            dpop2 = make_dpop("GET", uri, {'ath': ath, 'nonce': nonce})
            res = call_mgmt(USERS_EP, "GET", {
                'Accept': 'application/json',
                'Authorization': f'DPoP {self.access_token}',
                'DPoP': dpop2
            })
        
        # We don't assert 200 body content, only that it's no longer a DPoP failure
        assert res.status_code in [200, 403, 404]  # depends on your scopes; but not DPoP failure
    
    def test_replay_reusing_exact_same_dpop_proof_jti_fails(self):
        """Test that reusing the exact same DPoP proof jti fails."""
        uri = f"{okta_helper.okta_domain}{USERS_EP}"
        ath = okta_helper.generate_ath(self.access_token)
        one_proof = make_dpop("GET", uri, {'ath': ath})
        
        # First request (may need nonce retry)
        res1 = call_mgmt(USERS_EP, "GET", {
            'Accept': 'application/json',
            'Authorization': f'DPoP {self.access_token}',
            'DPoP': one_proof
        })
        
        if res1.status_code == 400 and 'dpop-nonce' in res1.headers:
            nonce = res1.headers['dpop-nonce']
            one_proof_with_nonce = make_dpop("GET", uri, {'ath': ath, 'nonce': nonce})
            res1 = call_mgmt(USERS_EP, "GET", {
                'Accept': 'application/json',
                'Authorization': f'DPoP {self.access_token}',
                'DPoP': one_proof_with_nonce
            })
            
            # Now try replaying that same nonce-bound proof again
            res2 = call_mgmt(USERS_EP, "GET", {
                'Accept': 'application/json',
                'Authorization': f'DPoP {self.access_token}',
                'DPoP': one_proof_with_nonce
            })
            assert res2.status_code >= 400
            assert res2.status_code < 500  # typically 400 invalid_dpop_proof or nonce error
        else:
            # If no nonce enforced, reuse the same proof directly
            res2 = call_mgmt(USERS_EP, "GET", {
                'Accept': 'application/json',
                'Authorization': f'DPoP {self.access_token}',
                'DPoP': one_proof
            })
            assert res2.status_code >= 400
            assert res2.status_code < 500
    
    def test_method_url_binding_proof_for_get_users_cannot_be_used_for_get_groups(self):
        """Test that proof for GET /users cannot be used for GET /groups."""
        uri_users = f"{okta_helper.okta_domain}{USERS_EP}"
        ath = okta_helper.generate_ath(self.access_token)
        proof_for_users = make_dpop("GET", uri_users, {'ath': ath})
        
        res = call_mgmt(GROUPS_EP, "GET", {
            'Accept': 'application/json',
            'Authorization': f'DPoP {self.access_token}',
            'DPoP': proof_for_users
        })
        
        assert res.status_code >= 400
        assert res.status_code < 500
    
    def test_ath_binding_proof_signed_with_ath_of_different_token_fails(self):
        """Test that proof signed with ath of a different token fails."""
        fake_ath = okta_helper.generate_ath("not-the-right-token")
        uri = f"{okta_helper.okta_domain}{USERS_EP}"
        bad_proof = make_dpop("GET", uri, {'ath': fake_ath})
        
        res = call_mgmt(USERS_EP, "GET", {
            'Accept': 'application/json',
            'Authorization': f'DPoP {self.access_token}',
            'DPoP': bad_proof
        })
        
        assert res.status_code >= 400
        assert res.status_code < 500
    
    def test_expired_proof_old_iat_is_rejected(self):
        """Test that expired proof with old iat is rejected."""
        priv = okta_helper._load_dpop_private_key()
        pub = okta_helper._load_dpop_public_key()
        uri = f"{okta_helper.okta_domain}{USERS_EP}"
        ath = okta_helper.generate_ath(self.access_token)
        
        # Build a proof with iat 10 minutes ago and a short exp already passed
        payload = {
            'htm': 'GET',
            'htu': uri,
            'iat': int(time.time()) - 600,
            'jti': okta_helper.get_new_jti(),
            'ath': ath
        }
        
        headers = {
            'typ': 'dpop+jwt',
            'alg': 'RS256',
            'jwk': pub
        }
        
        expired = jwt.encode(payload, priv, algorithm='RS256', headers=headers)
        
        res = call_mgmt(USERS_EP, "GET", {
            'Accept': 'application/json',
            'Authorization': f'DPoP {self.access_token}',
            'DPoP': expired
        })
        
        assert res.status_code >= 400
        assert res.status_code < 500
    
    def test_nonce_enforcement_reusing_nonce_bound_proof_fails_on_second_use(self):
        """Test that reusing a nonce-bound proof fails on a second use."""
        uri = f"{okta_helper.okta_domain}{USERS_EP}"
        ath = okta_helper.generate_ath(self.access_token)
        
        # First call to elicit a nonce if required
        res1 = call_mgmt(USERS_EP, "GET", {
            'Accept': 'application/json',
            'Authorization': f'DPoP {self.access_token}',
            'DPoP': make_dpop("GET", uri, {'ath': ath})
        })
        
        if res1.status_code == 400 and 'dpop-nonce' in res1.headers:
            nonce = res1.headers['dpop-nonce']
            proof_with_nonce = make_dpop("GET", uri, {'ath': ath, 'nonce': nonce})
            
            ok_call = call_mgmt(USERS_EP, "GET", {
                'Accept': 'application/json',
                'Authorization': f'DPoP {self.access_token}',
                'DPoP': proof_with_nonce
            })
            assert ok_call.status_code in [200, 403, 404]
            
            # Reuse same nonce-bound proof again -> should fail
            replay = call_mgmt(USERS_EP, "GET", {
                'Accept': 'application/json',
                'Authorization': f'DPoP {self.access_token}',
                'DPoP': proof_with_nonce
            })
            assert replay.status_code >= 400
            assert replay.status_code < 500
        else:
            # If nonce not enforced by tenant, skip
            assert True
