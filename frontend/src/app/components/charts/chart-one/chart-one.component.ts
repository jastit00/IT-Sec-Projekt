import { Component, inject } from '@angular/core';
import { ChartModule } from 'primeng/chart';
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../../api-client';
import { ChartUpdateService } from '../../../services/chart-update.service';
import { FormBuilder, ReactiveFormsModule } from '@angular/forms';
import { BaseChartComponent } from '../../base-chart/base-chart.component';

@Component({
  selector: 'app-chart-one',
  standalone: true,
  imports: [CommonModule, ChartModule, ReactiveFormsModule],
  templateUrl: './../chart-template.html',
  styleUrls: ['./../chart-styles.scss']
})
export class ChartOneComponent extends BaseChartComponent {
  protected defaultService = inject(DefaultService);
  protected fb = inject(FormBuilder);
  protected updateService = inject(ChartUpdateService)
  chartTitle = "Login attempts by IP-address";


  loadData(start?: string, end?: string): void {
    const observe = 'body';
    const reportProgress = false;

    const call = (start && end)
      ? this.defaultService.logfilesProcessedLoginsGet(start, end, observe, reportProgress)
      : this.defaultService.logfilesProcessedLoginsGet();

    call.subscribe((logins: any[]) => {
      const ipCountMap: { [ip: string]: number } = {};

      logins.forEach(entry => {
        const ip = entry.src_ip_address;
        ipCountMap[ip] = (ipCountMap[ip] || 0) + 1;
      });

      this.hasData = Object.keys(ipCountMap).length > 0;

      this.data = {
        labels: Object.keys(ipCountMap),
        datasets: [{
          label: 'attempted logins by IP',
          data: Object.values(ipCountMap),
          backgroundColor: this.getBackgroundColors(Object.keys(ipCountMap).length)
        }]
      };

      this.refreshChart();
    });
  }
}