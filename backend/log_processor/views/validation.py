import jwt
import requests
from django.http import JsonResponse
from jwt.algorithms import RSAAlgorithm
from functools import wraps

import os
from dotenv import load_dotenv

KEYCLOAK_URL = os.getenv('KEYCLOAK_URL', 'https://api.ads-logs.hs-esslingen.com/realms/FinalRealm')

def validate_keycloak_token(auth_header):
    """validate Keycloak Token """
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    
    token = auth_header.split(' ')[1]
    
    try:
        # fetch keycloak public keys
        response = requests.get(f'{KEYCLOAK_URL}/protocol/openid-connect/certs')
        try:
            keys_data = response.json().get('keys', [])
            if not keys_data:
                print(" Keycloak returned no keys:", response.text)
                return None
        except Exception as e:
            print(" Failed to parse certs response:", response.text)
            return None
        
        # decode token_header for kid
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get('kid')
        
        if not kid:
            print(" No 'kid' found in token header")
            return None
        
        # find fitting key
        key_data = None
        for key in keys_data:
            if key.get('kid') == kid:
                key_data = key
                break
        
        if not key_data:
            print(f" Key with kid '{kid}' not found")
            return None
        
        # convert
        public_key = RSAAlgorithm.from_jwk(key_data)
        
        # Decode and validate Token
        decoded = jwt.decode(
            token, 
            public_key, 
            algorithms=['RS256'], 
            audience='account',
            options={"verify_exp": True}
        )
        return decoded
        
    except Exception as e:
        print(f"Token validation error: {e}")
        return None

def keycloak_required(view_func):
    """Decorator for Token-Validation"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):  
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        user_data = validate_keycloak_token(auth_header)
        
        if not user_data:
            return JsonResponse({'error': 'Invalid or missing token'}, status=401)
        
        # Append User Data
        request.keycloak_user = user_data
        return view_func(request, *args, **kwargs)  
    
    return wrapper