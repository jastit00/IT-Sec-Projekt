import jwt
import requests
from django.http import JsonResponse
from functools import wraps
from jwt.algorithms import RSAAlgorithm

KEYCLOAK_URL = "http://localhost:8080/realms/FinalRealm"

def validate_keycloak_token(auth_header):
    """Keycloak Token validieren"""
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    
    token = auth_header.split(' ')[1]
    
    try:
        # Keycloak public keys holen
        response = requests.get(f'{KEYCLOAK_URL}/protocol/openid-connect/certs')
        try:
            keys_data = response.json().get('keys', [])
            if not keys_data:
                print(" Keycloak returned no keys:", response.text)
                return None
        except Exception as e:
            print(" Failed to parse certs response:", response.text)
            return None
        
        # Token Header dekodieren um die kid (key ID) zu bekommen
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get('kid')
        
        if not kid:
            print(" No 'kid' found in token header")
            return None
        
        # Den passenden Key finden
        key_data = None
        for key in keys_data:
            if key.get('kid') == kid:
                key_data = key
                break
        
        if not key_data:
            print(f" Key with kid '{kid}' not found")
            return None
        
        # JWK zu PEM konvertieren
        public_key = RSAAlgorithm.from_jwk(key_data)
        
        # Token dekodieren und validieren
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