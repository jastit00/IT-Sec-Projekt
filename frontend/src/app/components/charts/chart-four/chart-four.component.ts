import { Component, inject } from '@angular/core';
import { ChartModule } from 'primeng/chart';
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../../api-client';
import { ChartUpdateService } from '../../../services/chart-update.service';
import { FormBuilder, ReactiveFormsModule } from '@angular/forms';
import { BaseChartComponent } from '../../base-chart/base-chart.component';

@Component({
  selector: 'app-chart-four',
  standalone: true,
  imports: [CommonModule, ChartModule, ReactiveFormsModule],
  templateUrl: './chart-four.component.html',
  styleUrls: ['./chart-four.component.scss']
})
export class ChartFourComponent extends BaseChartComponent {
  protected defaultService = inject(DefaultService);
  protected fb = inject(FormBuilder);
  protected updateService = inject(ChartUpdateService)


  loadData(start?: string, end?: string) {

    
    const call =  this.defaultService.logfilesUnifiedEventsGet();
    const typeCountMap: { [type: string]: number } = {};


    call.subscribe((events: any[]) => {


    const startDate = start ? new Date(start) : null;
    const endDate = end ? new Date(end) : null;

    events.forEach(event => {
     const isIncident = event.event_type === 'incident';
      const eventTime = new Date(event.timestamp);
      const inRange = (!startDate || eventTime >= startDate) && (!endDate || eventTime <= endDate);

      if (isIncident && inRange) {
        const type = event.incident_type;
        typeCountMap[type] = (typeCountMap[type] || 0) + 1;
      }
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
          //label: 'Login-Versuche pro IP',
          data: Object.values(typeCountMap),
          backgroundColor: ['#F94144', '#F3722C', '#F8961E', '#F9844A', '#F9C74F', '#90BE6D', '#43AA8B', '#4D908E', '#577590', '#277DA1']
        }]
      };
          this.refreshChart();
    });
  }
}