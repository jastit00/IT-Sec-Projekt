import jwt
import requests
from django.http import JsonResponse
from functools import wraps

KEYCLOAK_URL = "http://localhost:8080/realms/FinalRealm"

def validate_keycloak_token(auth_header):
    """Keycloak Token validieren"""
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    
    token = auth_header.split(' ')[1]
    
    try:
        # Keycloak public keys holen
        response = requests.get(f'{KEYCLOAK_URL}/protocol/openid_connect/certs')
        keys = response.json()['keys']
        
        # Token dekodieren und validieren
        decoded = jwt.decode(token, keys, algorithms=['RS256'], audience='account')
        return decoded  # Enthält username, email, roles, etc.
    except Exception as e:
        print(f"Token validation error: {e}")
        return None

def keycloak_required(view_func):
    """Decorator für Token-Validierung"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        user_data = validate_keycloak_token(auth_header)
        
        if not user_data:
            return JsonResponse({'error': 'Invalid or missing token'}, status=401)
        
        # User-Daten an Request anhängen
        request.keycloak_user = user_data
        return view_func(request, *args, **kwargs)
    
    return wrapper