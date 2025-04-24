import { CanActivateFn, Router } from '@angular/router';
import { keycloak } from './../auth/keycloak.service';

export const authGuard: CanActivateFn = async (route, state) => {
  const isAuthenticated = keycloak.authenticated;

  // Keycloak ist noch nicht initialisiert (als Fallback)
  if (isAuthenticated === undefined) {
    await keycloak.init({
      onLoad: 'login-required',
      checkLoginIframe: false
    });
  }

  if (keycloak.authenticated) {
    return true;
  } else {
    // Falls nicht eingeloggt: Leite zum Login
    await keycloak.login({
      redirectUri: window.location.href // zurück zur aktuellen Seite nach Login
    });
    return false;
  }
};
