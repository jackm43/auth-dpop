"""
Main application demonstrating Okta DPoP authentication.

This script shows how to authenticate with Okta using DPoP tokens
and make authenticated API calls to retrieve user information.
"""

import json
from okta_service import okta_service


def main():
    """
    Main function demonstrating Okta DPoP authentication and API usage.
    
    Authenticates with Okta and retrieves a list of users from the
    Okta Management API using DPoP-protected requests.
    """
    # Authenticate and get access token
    access_token = okta_service.authenticate()
    
    if not access_token:
        print("Failed to authenticate with Okta")
        return
    
    # Make an authenticated API call to get users
    users_resp = okta_service.management_api_call("/api/v1/users", "GET")
    
    if users_resp.status_code == 200:
        resp_body = users_resp.json()
        print(f"Users List: {json.dumps(resp_body, indent=2)}\n")
    else:
        print(f"API error: {users_resp.status_code}")
        print(f"Response: {users_resp.text}")


if __name__ == "__main__":
    main()
