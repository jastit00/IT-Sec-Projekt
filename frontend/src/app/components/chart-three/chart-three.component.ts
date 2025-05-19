import { HttpClient } from '@angular/common/http';
import { Component, inject, OnInit } from '@angular/core';
import { ChartModule } from 'primeng/chart';  
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../api-client';
import { ChartUpdateService } from '../../services/chart-update.service';

@Component({
  selector: 'app-chart-three',
  standalone: true,
  imports: [CommonModule, ChartModule],
  templateUrl: './chart-three.component.html',
  styleUrl: './chart-three.component.scss'
})

export class ChartThreeComponent implements OnInit{
  
  private defaultService = inject(DefaultService);
  private updateService = inject(ChartUpdateService);
  
  data = {
    labels: ['Ip1', 'Ip2', 'Ip3', 'Ip4', 'Ip5'],
    datasets: [{
      label: 'attempted logins by IP',
      data: [0, 25, 50, 75, 100], //stimmen noch nicht
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
    
  
  const TARGET_DST_IP = '192.168.0.88';  // festgelegte Ziel-IP

  this.defaultService.logfilesDosPacketsGet().subscribe((entries: any[]) => {
    const packetMap: { [srcIp: string]: number } = {};

    entries.forEach(entry => {
      if (entry.dst_ip_address === TARGET_DST_IP) {
        const srcIp = entry.src_ip_address;
        const packets = parseInt(entry.packets, 10);  // Wichtig: von string zu number

        if (!isNaN(packets)) {
          packetMap[srcIp] = (packetMap[srcIp] || 0) + packets;
        }
      }
    });

    const labels = Object.keys(packetMap);
    const dataValues = Object.values(packetMap);

    this.data = {
      labels,
      
      datasets: [{
        label: 'attempted logins by IP',
        data: dataValues,
        backgroundColor: ['#FF6384']
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