import { Provider } from '@angular/core';
import { Configuration } from './configuration';


export function provideLogfileApi(config: { rootUrl: string }): Provider[] {
  return [
    {
      provide: Configuration,
      useValue: new Configuration({ basePath: config.rootUrl })
    }
  ];
}
