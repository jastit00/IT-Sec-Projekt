import { RouterModule, Routes } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { CriticalEventsComponent } from './components/critical-events/critical-events.component';
import { AllEventsComponent } from './components/all-events/all-events.component';
import { NgModule } from '@angular/core';

export const routes: Routes = [
    { path: '', component: HomeComponent },
    { path: 'critical-events', component: CriticalEventsComponent },
    { path: 'all-events', component: AllEventsComponent }
];