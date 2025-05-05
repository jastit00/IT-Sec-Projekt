import { Component, inject } from '@angular/core';
import { ChartModule } from 'primeng/chart';  
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../api-client';

@Component({
  selector: 'app-chart-two',
  standalone: true,
  imports: [CommonModule, ChartModule],
  templateUrl: './chart-two.component.html',
  styleUrl: './chart-two.component.scss'
})
export class ChartTwoComponent {
  private defaultService = inject(DefaultService);
  
  data: any = {
    labels: [],
    datasets: [{
      label: 'Login-Versuche pro IP',
      data: [],
      backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
    }]
  };
  
  ngOnInit(): void {
    this.defaultService.logfilesProcessedLoginsGet().subscribe((logins: any[]) => {
      const ipCountMap: { [ip: string]: number } = {};
  
      logins.forEach(entry => {
        if (entry.result === 'failed') {
        const ip = entry.ip_address;
        ipCountMap[ip] = (ipCountMap[ip] || 0) + 1;
        }
      });
  
      this.data = {
        labels: Object.keys(ipCountMap),
        datasets: [{
          label: 'Login-Versuche pro IP',
          data: Object.values(ipCountMap),
          
        }]
      };
    });
  }
  
  options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',  // Legende unter dem Diagramm
        align: 'center',    // Zentrierte Ausrichtung der Legende
        labels: {
          boxWidth: 25,     // Breite des Farb-Kastens
          padding: 15,      // Abstand zwischen den Labels
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