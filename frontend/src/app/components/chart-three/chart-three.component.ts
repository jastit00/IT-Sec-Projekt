import { HttpClient } from '@angular/common/http';
import { Component, inject, OnInit } from '@angular/core';
import { ChartModule } from 'primeng/chart';  
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../api-client';

@Component({
  selector: 'app-chart-three',
  standalone: true,
  imports: [CommonModule, ChartModule],
  templateUrl: './chart-three.component.html',
  styleUrl: './chart-three.component.scss'
})

export class ChartThreeComponent implements OnInit{
  
  private defaultService = inject(DefaultService);
  
  data = {
    labels: ['Ip1', 'Ip2', 'Ip3', 'Ip4', 'Ip5'],
    datasets: [{
      data: [0, 25, 50, 75, 100], //stimmen noch nicht
      backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
    }]
  };

  ngOnInit(): void {  // Requests nach DST IP durchsuchen
    this.defaultService.logfilesProcessedLoginsGet().subscribe((http_requests: any[]) => {
      const ipCountMap: { [ip: string]: number } = {};
  
      http_requests.forEach(entry => {  // DST IP in Chart anzeigen
        const target_ip = entry.ip_address;
        ipCountMap[target_ip] = (ipCountMap[target_ip] || 0) + 1;
      });
  
      this.data = {
        labels: Object.keys(ipCountMap),
        datasets: [{
          //label: 'Login-Versuche pro IP',
          data: Object.values(ipCountMap),
          backgroundColor: []
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
  onSettingsClick() {
    console.log('Test Click');
  }
}