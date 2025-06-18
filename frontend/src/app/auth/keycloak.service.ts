
import Keycloak from 'keycloak-js';
import { environment } from '../../environments/environment';

export const keycloak = new Keycloak({
    url: environment.keycloakUrl,
    realm: 'FinalRealm',
    clientId: 'my-security-client'
});

export function initKeycloak(): Promise<boolean> {
  return keycloak.init({
    onLoad: 'login-required',
    checkLoginIframe: false
  });
}

export function logout(): void {
  keycloak.logout({
    redirectUri: environment.redirectUri
  });
}

export function updatefunction(userId: string){
  
    fetch(`${environment.keycloakUrl}/realms/FinalRealm/users/${userId}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + keycloak.token
    },
    body: JSON.stringify({
      attributes: {
        key: ['test3'],
      }
    })
  });
}

