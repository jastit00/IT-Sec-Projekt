import { bootstrapApplication } from '@angular/platform-browser';
import { appConfig } from './app/app.config';
import { AppComponent } from './app/app.component';
import { initKeycloak } from './app/auth/keycloak.service';
import { MenubarModule } from 'primeng/menubar';
import { provideHttpClient } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { routes } from './app/app.routes';
import { provideLogfileApi } from './app/api-client/api-provider';
import { Configuration } from './app/api-client';
import { keycloak } from './app/auth/keycloak.service';
import { environment } from './environments/environment';
import { enableProdMode } from '@angular/core';


if (environment.production) {
  enableProdMode();
}


export function createApiConfiguration(): Configuration {
  return new Configuration({
    basePath: ${environment.backendUrl}/api`
    accessToken: () => keycloak.token || ''
  });
}


initKeycloak().then(() => {
  bootstrapApplication(AppComponent, {
    providers: [
      provideRouter(routes),
      provideHttpClient(),

      provideLogfileApi({ rootUrl: ${environment.backendUrl}/api` }),
      {
        provide: Configuration,
        useFactory: createApiConfiguration
      }

    ]
  }).catch(err => console.error(err));
});

