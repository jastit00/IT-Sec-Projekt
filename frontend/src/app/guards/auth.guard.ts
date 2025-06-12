import { CanActivateFn, Router } from '@angular/router';
import { keycloak } from './../auth/keycloak.service';
import { environment } from '../../environments/environment';

export const authGuard: CanActivateFn = async (route, state) => {

  if (keycloak.authenticated) {
    return true;
  } else {
    await keycloak.login({
      redirectUri: environment.redirectUri
    });
    return false;
  }
};