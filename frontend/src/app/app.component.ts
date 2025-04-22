import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { TestComponent } from './components/test/test.component';
import { ChartsComponent } from './components/charts/charts.component';
import { ChartModule } from 'primeng/chart'; 
import { CommonModule } from '@angular/common';  
import { HomeComponent } from './home/home.component';
import { HeaderComponent } from './components/header/header.component';
import { AllEventsComponent } from './components/all-events/all-events.component';

@Component({
  selector: 'app-root',
  standalone: true,  
  imports: [CommonModule, RouterOutlet, HomeComponent, HeaderComponent, TestComponent, ChartsComponent, ChartModule, AllEventsComponent],
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent {
  title = 'audit_visualization';
}
