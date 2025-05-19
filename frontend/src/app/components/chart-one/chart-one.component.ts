import { Component, inject, Input, OnInit, SimpleChanges } from '@angular/core';
import { ChartModule } from 'primeng/chart';
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../api-client';
import { FormBuilder, FormGroup } from '@angular/forms';
import { ChartUpdateService } from '../../services/chart-update.service';

@Component({
  selector: 'app-chart-one',
  standalone: true,
  imports: [CommonModule, ChartModule],
  templateUrl: './chart-one.component.html',
  styleUrls: ['./chart-one.component.scss']
})

export class ChartOneComponent implements OnInit {
  private defaultService = inject(DefaultService);
  private updateService = inject(ChartUpdateService);

  data: any = {
    labels: [],
    datasets: [{
      label: 'attempted logins by IP',
      data: [],
      backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
    }]
  };
ngOnInit(): void {
  
  this.loadData();
  this.updateService.updateChart$.subscribe(() => {
    console.log('in der component');
    this.loadData();
  });

  }

 loadData() {
    this.defaultService.logfilesProcessedLoginsGet().subscribe((logins: any[]) => {
      const ipCountMap: { [ip: string]: number } = {};
  
      logins.forEach(entry => {
        const ip = entry.ip_address;
        ipCountMap[ip] = (ipCountMap[ip] || 0) + 1;
      });

      this.data = {
        labels: Object.keys(ipCountMap),
        datasets: [{
          label: 'attempted logins by IP',
          data: Object.values(ipCountMap),
          backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
          
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
