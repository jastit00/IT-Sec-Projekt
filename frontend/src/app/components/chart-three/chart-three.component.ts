import { HttpClient } from '@angular/common/http';
import { Component, inject, OnInit } from '@angular/core';
import { ChartModule } from 'primeng/chart';  
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../api-client';
import { FormBuilder, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { ChartUpdateService } from '../../services/chart-update.service';

@Component({
  selector: 'app-chart-three',
  standalone: true,
  imports: [CommonModule, ChartModule, ReactiveFormsModule],
  templateUrl: './chart-three.component.html',
  styleUrl: './chart-three.component.scss'
})

export class ChartThreeComponent implements OnInit{
  
  private defaultService = inject(DefaultService);
  private updateService = inject(ChartUpdateService);
  private fb = inject(FormBuilder);

  showSettings = false;
  dateForm!: FormGroup;
  availableDstIps: string[] = [];
  
  data = {
    labels: ['Ip1', 'Ip2', 'Ip3', 'Ip4', 'Ip5'],
    datasets: [{
      label: 'attempted logins by IP',
      data: [0, 25, 50, 75, 100], //stimmen noch nicht
      backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
    }]
  };


  ngOnInit(): void {
  
  this.dateForm = this.fb.group({
    start: [null],
    end: [null],
    chartType: ['pie'],
    targetDstIp: [null] 
  });


  this.loadData();
  this.updateService.updateChart$.subscribe(() => {
    this.loadData();
  });

  }

 loadData(start?: string, end?: string) {

    const observe = 'body';
    const reportProgress = false;
    
    const call = (start && end)
    

    ? this.defaultService.logfilesDosPacketsGet(start, end, observe, reportProgress)
    : this.defaultService.logfilesDosPacketsGet();


    call.subscribe((entries: any[]) => {

    const dstIpsSet = new Set<string>();
      entries.forEach(e => dstIpsSet.add(e.dst_ip_address));
      const uniqueIps = Array.from(dstIpsSet);
      this.availableDstIps = uniqueIps;

    const currentTarget = this.dateForm.get('targetDstIp')?.value;
      if (!currentTarget && uniqueIps.length > 0) {
        this.dateForm.patchValue({ targetDstIp: uniqueIps[0] });
      }
    
    const TARGET_DST_IP = this.dateForm.get('targetDstIp')?.value;

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
    console.log("click");
    this.showSettings = !this.showSettings;
    
}

onApply() {
    const startDate = this.dateForm.get('start')?.value;
    const endDate = this.dateForm.get('end')?.value;
    

    const start = startDate ? new Date(startDate).toISOString() : undefined;
    const end = endDate ? new Date(endDate).toISOString() : undefined;
    
    this.loadData(start, end);
    this.showSettings = false;
  }

onReset() {
  const firstIp = this.availableDstIps[0] || null;
  this.dateForm.patchValue({
    start: undefined,
    end: undefined,
    chartType: 'pie',
    targetDstIp: firstIp
  });

  this.loadData();
} 
}