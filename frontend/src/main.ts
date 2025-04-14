import { bootstrapApplication } from '@angular/platform-browser';
import { appConfig } from './app/app.config';
import { AppComponent } from './app/app.component';
import { initKeycloak } from './app/auth/keycloak.service';
import { MenubarModule } from 'primeng/menubar';

bootstrapApplication(AppComponent, appConfig)
  .catch((err) => console.error(err));

initKeycloak().then(() => {
  bootstrapApplication(AppComponent)
    .catch(err => console.error(err));
});