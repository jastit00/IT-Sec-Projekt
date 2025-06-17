import { ApplicationConfig, provideZoneChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { providePrimeNG } from 'primeng/config';
import Aura from '@primeng/themes/aura';

import { routes } from './app.routes';
import { provideCharts, withDefaultRegisterables } from 'ng2-charts';

export const appConfig: ApplicationConfig = {
  providers: [provideZoneChangeDetection({ eventCoalescing: true }), provideRouter(routes), provideCharts(withDefaultRegisterables()), provideAnimationsAsync(),
    providePrimeNG({
      theme: {
          preset: Aura,
          options: {
              prefix: 'p',
              darkModeSelector: '',
              cssLayer: false
          }
      }
  })]
};
