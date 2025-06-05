import { Component, inject, Input } from '@angular/core';
import { ChartModule } from 'primeng/chart';
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../../api-client';
import { ChartUpdateService } from '../../../services/chart-update.service';
import { FormBuilder, ReactiveFormsModule } from '@angular/forms';
import { BaseChartComponent } from '../../base-chart/base-chart.component';

@Component({
  selector: 'app-chart-three',
  standalone: true,
  imports: [CommonModule, ChartModule, ReactiveFormsModule],
  templateUrl: './../chart-template.html',
  styleUrls: ['./../chart-styles.scss']
})
export class ChartThreeComponent extends BaseChartComponent {
  override  showTargetIpSelect = true;
  protected defaultService = inject(DefaultService);
  protected fb = inject(FormBuilder);
  protected updateService = inject(ChartUpdateService);
  chartTitle = "Forwarded packets by source IP";


  loadData(start?: string, end?: string) {

    const observe = 'body';
    const reportProgress = false;
    this.dateForm.addControl('targetDstIp', this.fb.control(''));
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
        const packets = parseInt(entry.packets, 10);  

        if (!isNaN(packets)) {
          packetMap[srcIp] = (packetMap[srcIp] || 0) + packets;
        }
      }
    });

    const labels = Object.keys(packetMap);
    const dataValues = Object.values(packetMap);

    if(dataValues.length===0){
        this.hasData = false;
      }
      else {
        this.hasData = true;
        
      }

    this.data = {
      labels,
      
      datasets: [{
        label: 'forwarded packets by source IP',
        data: dataValues,
        backgroundColor: this.getBackgroundColors(dataValues.length)
      }]
    };
    this.refreshChart();
  });
  
}
}