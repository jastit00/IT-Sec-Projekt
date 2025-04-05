
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
