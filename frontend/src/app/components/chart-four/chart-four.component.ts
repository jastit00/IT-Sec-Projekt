import { Component, inject, OnInit } from '@angular/core';
import { ChartModule } from 'primeng/chart';  
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../api-client';

@Component({
  selector: 'app-chart-four',
  standalone: true,
  imports: [CommonModule, ChartModule],
  templateUrl: './chart-four.component.html',
  styleUrl: './chart-four.component.scss'
})

export class ChartFourComponent implements OnInit {
  
  private defaultService = inject(DefaultService);
  
  data = {
    labels: ['Ip1', 'Ip2', 'Ip3', 'Ip4', 'Ip5'],
    datasets: [{
      data: [0, 25, 25, 25, 25],
      backgroundColor: ['#F94144', '#F3722C', '#F8961E', '#F9844A', '#F9C74F', '#90BE6D', '#43AA8B', '#4D908E', '#577590', '#277DA1']
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
          backgroundColor: ['#F94144', '#F3722C', '#F8961E', '#F9844A', '#F9C74F', '#90BE6D', '#43AA8B', '#4D908E', '#577590', '#277DA1']
        }]
      };
    });
  }
  
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
  
  onSettingsClick() {
    console.log('Test Click');
  }
  
}