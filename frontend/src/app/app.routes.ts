import { Routes } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { CriticalEventsComponent } from './components/critical-events/critical-events.component';
import { AllEventsComponent } from './components/all-events/all-events.component';
import { authGuard } from './guards/auth.guard';
import { NotFoundComponent } from './components/not-found/not-found.component';
import { TeapotComponent } from './components/teapot/teapot.component';

export const routes: Routes = [
    { path: 'dashboard/:presetId', component: HomeComponent, canActivate: [authGuard] },
    { path: 'critical-events', component: CriticalEventsComponent, canActivate: [authGuard] },
    { path: 'all-events', component: AllEventsComponent, canActivate: [authGuard] },
    { path: 'not-found', component: NotFoundComponent },
    { path: 'hidden-backdoor', component: TeapotComponent },
    { path: 'dashboard', redirectTo: 'dashboard/1', pathMatch: 'full' },
    { path: '', redirectTo: 'dashboard', pathMatch: 'full'},
    { path: '**', redirectTo: 'not-found' }
];