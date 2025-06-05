import { Component, inject } from '@angular/core';
import { ChartModule } from 'primeng/chart';
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../../api-client';
import { FormBuilder, ReactiveFormsModule } from '@angular/forms';
import { BaseChartComponent } from '../../base-chart/base-chart.component';
import { ChartUpdateService } from '../../../services/chart-update.service';

@Component({
  selector: 'app-chart-eight',
  standalone: true,
  imports: [CommonModule, ChartModule, ReactiveFormsModule],
  templateUrl: './../chart-template.html',
  styleUrls: ['./../chart-styles.scss']
})
export class ChartEightComponent extends BaseChartComponent {
  protected defaultService = inject(DefaultService);
  protected fb = inject(FormBuilder);
  protected updateService = inject(ChartUpdateService);
  chartTitle = "Configurationchanges by type";

  loadData(start?: string, end?: string) {

    const observe = 'body';
    const reportProgress = false;
  
    const call = (start && end)
    

    ? this.defaultService.logfilesConfigChangesGet(start, end, observe, reportProgress)
    : this.defaultService.logfilesConfigChangesGet();


    call.subscribe((logins: any[]) => {
      const typeCountMap: { [type: string]: number } = {};
  
      logins.forEach(entry => {
        const type = entry.table;
        typeCountMap[type] = (typeCountMap[type] || 0) + 1;
      });

      if(Object.values(typeCountMap).length ===0){
        this.hasData = false;
      }
      else {
        this.hasData = true;
      }

      this.data = {
        labels: Object.keys(typeCountMap),
        datasets: [{
          label: 'times edited',
          data: Object.values(typeCountMap),
          backgroundColor: ['#F94144', '#F3722C', '#F8961E', '#F9844A', '#F9C74F', '#90BE6D', '#43AA8B', '#4D908E', '#577590', '#277DA1']
          
        }]
      };
      this.refreshChart();
    });
  }
}