import { Component } from '@angular/core';
import { ChartModule } from 'primeng/chart';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-chart-one',
  standalone: true,
  imports: [CommonModule, ChartModule],
  templateUrl: './chart-one.component.html',
  styleUrls: ['./chart-one.component.scss']
})
export class ChartOneComponent {
  data = {
    labels: ['IP1', 'IP2', 'IP3', 'IP4', 'IP5'], 
    datasets: [{
      label: 'Login-Anteile',
      data: [0, 25, 25, 25, 25], 
    }]
  };

  options = {
    responsive: true,
    scale: {
      ticks: {
        beginAtZero: true,
        max: 100, 
        stepSize: 20
      }
    },
    plugins: {
      legend: {
        position: 'top', 
        labels: {
          font: {
            size: 14
          }
        }
      },
    },
    layout: {
      padding: {
        top: 0,  
        right: 0,
        bottom: 0,
        left: 0
      }
    }
  };
}
