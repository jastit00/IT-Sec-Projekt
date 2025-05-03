import { bootstrapApplication } from '@angular/platform-browser';
import { appConfig } from './app/app.config';
import { AppComponent } from './app/app.component';
import { initKeycloak } from './app/auth/keycloak.service';
import { MenubarModule } from 'primeng/menubar';
import { provideHttpClient } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { routes } from './app/app.routes';
import { provideLogfileApi } from './app/api-client/api-provider';



initKeycloak().then(() => {
  bootstrapApplication(AppComponent, {
    providers: [
      provideRouter(routes),
      provideHttpClient(),
      provideLogfileApi({ rootUrl: 'http://localhost:8000/api' })
    ]
  }).catch(err => console.error(err));
});