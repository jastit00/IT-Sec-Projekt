import { Component, inject, OnInit } from '@angular/core';
import { ChartModule } from 'primeng/chart';
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../api-client';

@Component({
  selector: 'app-chart-one',
  standalone: true,
  imports: [CommonModule, ChartModule],
  templateUrl: './chart-one.component.html',
  styleUrls: ['./chart-one.component.scss']
})
export class ChartOneComponent implements OnInit {

  private defaultService = inject(DefaultService);
  
  data: any = {
    labels: [],
    datasets: [{
      label: 'Login-Versuche pro IP',
      data: [],
      backgroundColor: '#42A5F5'
    }]
  };
  
  ngOnInit(): void {
    this.defaultService.logfilesProcessedLoginsGet().subscribe((logins: any[]) => {
      const ipCountMap: { [ip: string]: number } = {};
  
      logins.forEach(entry => {
        const ip = entry.ip_address;
        ipCountMap[ip] = (ipCountMap[ip] || 0) + 1;
      });
  
      this.data = {
        labels: Object.keys(ipCountMap),
        datasets: [{
          label: 'Login-Versuche pro IP',
          data: Object.values(ipCountMap),
          backgroundColor: '#42A5F5'
        }]
      };
    });
  }

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
