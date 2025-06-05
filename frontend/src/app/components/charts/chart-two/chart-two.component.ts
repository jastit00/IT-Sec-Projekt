import { Component, inject } from '@angular/core';
import { ChartModule } from 'primeng/chart';
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../../api-client';
import { FormBuilder, ReactiveFormsModule } from '@angular/forms';
import { BaseChartComponent } from '../../base-chart/base-chart.component';
import { ChartUpdateService } from '../../../services/chart-update.service';

@Component({
  selector: 'app-chart-two',
  standalone: true,
  imports: [CommonModule, ChartModule, ReactiveFormsModule],
  templateUrl: './chart-two.component.html',
  styleUrls: ['./chart-two.component.scss']
})
export class ChartTwoComponent extends BaseChartComponent {
  protected defaultService = inject(DefaultService);
  protected fb = inject(FormBuilder);
  protected updateService = inject(ChartUpdateService)

  loadData(): void {
    const startDate = this.dateForm.get('start')?.value;
    const endDate = this.dateForm.get('end')?.value;

    const start = startDate ? new Date(startDate).toISOString() : undefined;
    const end = endDate ? new Date(endDate).toISOString() : undefined;

    const call = (start && end)
      ? this.defaultService.logfilesProcessedLoginsGet(start, end, 'body', false)
      : this.defaultService.logfilesProcessedLoginsGet();

    call.subscribe((logins: any[]) => {
      const ipCountMap: { [ip: string]: number } = {};
      logins.forEach(entry => {
        if (entry.result === 'failed') {
          ipCountMap[entry.src_ip_address] = (ipCountMap[entry.src_ip_address] || 0) + 1;
        }
      });

      this.hasData = Object.keys(ipCountMap).length > 0;

      this.data = {
        labels: Object.keys(ipCountMap),
        datasets: [{
          label: 'failed logins by IP',
          data: Object.values(ipCountMap),
          backgroundColor: this.getBackgroundColors(Object.keys(ipCountMap).length)
        }]
      };
      this.refreshChart();
    });
  }
}