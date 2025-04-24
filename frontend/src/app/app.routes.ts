import { Routes } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { CriticalEventsComponent } from './components/critical-events/critical-events.component';
import { AllEventsComponent } from './components/all-events/all-events.component';
import { authGuard } from './guards/auth.guard';
import { NotFoundComponent } from './components/not-found/not-found.component';

export const routes: Routes = [
    { path: 'dashboard', component: HomeComponent, canActivate: [authGuard] },
    { path: 'critical-events', component: CriticalEventsComponent, canActivate: [authGuard] },
    { path: 'all-events', component: AllEventsComponent, canActivate: [authGuard] },
    { path: 'not-found', component: NotFoundComponent },
    { path: '**', redirectTo: 'not-found' }
];