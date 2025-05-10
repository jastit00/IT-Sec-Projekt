import { CanActivateFn, Router } from '@angular/router';
import { keycloak } from './../auth/keycloak.service';

export const authGuard: CanActivateFn = async (route, state) => {
  // Check if we're already in a redirect (to break the loop)
  if (window.location.href.includes('code=') && window.location.href.includes('session_state=')) {
    return true;
  }

  if (keycloak.authenticated) {
    return true;
  } else {
    await keycloak.login({
      redirectUri: window.location.origin + state.url
    });
    return false;
  }
};