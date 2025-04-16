import { Component } from '@angular/core';
import { ChartModule } from 'primeng/chart';  
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-chart-four',
  standalone: true,
  imports: [CommonModule, ChartModule],
  templateUrl: './chart-four.component.html',
  styleUrl: './chart-four.component.scss'
})
export class ChartFourComponent {
  data = {
    labels: ['Ip1', 'Ip2', 'Ip3', 'Ip4', 'Ip5'],
    datasets: [{
      data: [0, 25, 25, 25, 25],
      backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
    }]
  };
  
  options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right',  // Legende rechts vom Diagramm, generell können wir ja dann links eventuell noch ein Zahnrad vllt machen mit individuellen Einstellungen für das Diagram
        align: 'center',    // Ausrichtung Legende
        labels: {
          boxWidth: 25,     // Breite Farb Kasten
          padding: 15,      // Abstand Labels
          font: {
            size: 20
          }
        }
      },
      tooltip: {
        backgroundColor: 'rgba(0, 0, 0, 0.7)',
        padding: 10,
        titleFont: {
          size: 14
        },
        bodyFont: {
          size: 13
        }
      }
    }
  };
}