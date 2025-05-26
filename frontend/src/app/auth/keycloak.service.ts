
import Keycloak from 'keycloak-js';

export const keycloak = new Keycloak({
    url: 'http://localhost:8080',
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
    redirectUri: 'http://localhost:4200/dashboard'
  });
}

export function updatefunction(userId: string){
  
    fetch('http://localhost:8080/dashboard/auth/admin/realms/FinalRealm/users/5bff8e57-8cbd-4ddd-acbf-932eef0944a4', {
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

