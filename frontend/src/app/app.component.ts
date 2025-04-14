import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { TestComponent } from './components/test/test.component';
import { ChartsComponent } from './components/charts/charts.component';
import { ChartModule } from 'primeng/chart'; 
import { CommonModule } from '@angular/common';  

@Component({
  selector: 'app-root',
  standalone: true,  
  imports: [CommonModule, RouterOutlet, TestComponent, ChartsComponent, ChartModule],
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent {
  title = 'audit_visualization';
}
