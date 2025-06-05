import { Component, inject } from '@angular/core';
import { ChartModule } from 'primeng/chart';
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../../api-client';
import { FormBuilder, ReactiveFormsModule } from '@angular/forms';
import { BaseChartComponent } from '../../base-chart/base-chart.component';
import { ChartUpdateService } from '../../../services/chart-update.service';

@Component({
  selector: 'app-chart-six',
  standalone: true,
  imports: [CommonModule, ChartModule, ReactiveFormsModule],
  templateUrl: './../chart-template.html',
  styleUrls: ['./../chart-styles.scss']
})
export class ChartSixComponent extends BaseChartComponent {
  protected defaultService = inject(DefaultService);
  protected fb = inject(FormBuilder);
  protected updateService = inject(ChartUpdateService);
  chartTitle ="Potential DDOS connections";

  loadData(start?: string, end?: string) {
    
    const observe = 'body';
    const reportProgress = false;
     const labels: string[] = [];
    const call = (start && end)
    

    ? this.defaultService.logfilesDdosPacketsGet(start, end, observe, reportProgress)
    : this.defaultService.logfilesDdosPacketsGet();


    call.subscribe((entries: any[]) => {
       

      if(entries.length === 0){
        this.hasData = false;
      }
      else {
        this.hasData = true;
      }
      
      const labels: string[] = [];
      const dataValues: number[] = [];

      entries.forEach(entry => {
        
        const dst = entry.dst_ip_address;
        
        const packetCount = parseInt(entry.packets, 10);
        
        labels.push(dst);
        dataValues.push(packetCount);
      

      this.data = {
        labels,
        datasets: [{
          label: 'number of packets',
          data: dataValues,
          backgroundColor: ['#F94144', '#F3722C', '#F8961E', '#F9844A', '#F9C74F', '#90BE6D', '#43AA8B', '#4D908E', '#577590', '#277DA1']
          
        }]
      };
      });
      this.refreshChart();
    });
  }
}