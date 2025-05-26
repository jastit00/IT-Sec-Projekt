import { Component, inject, Input, OnInit, SimpleChanges } from '@angular/core';
import { ChartModule } from 'primeng/chart';
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../api-client';
import { FormBuilder, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { ChartUpdateService } from '../../services/chart-update.service';

@Component({
  selector: 'app-chart-six',
  standalone: true,
  imports: [CommonModule, ChartModule, ReactiveFormsModule],
  templateUrl: './chart-six.component.html',
  styleUrls: ['./chart-six.component.scss']
})

export class ChartSixComponent implements OnInit {
  private defaultService = inject(DefaultService);
  private updateService = inject(ChartUpdateService);
  private fb = inject(FormBuilder);

 showSettings = false;
 dateForm!: FormGroup;
 hasData = false;

  data: any = {
    labels: [],
    datasets: [{
      label: 'ddos by source ip',
      data: [],
      backgroundColor: ['#F94144', '#F3722C', '#F8961E', '#F9844A', '#F9C74F', '#90BE6D', '#43AA8B', '#4D908E', '#577590', '#277DA1']
    }]
  };
ngOnInit(): void {
  
  this.dateForm = this.fb.group({
      start: [null],
      end: [null],
      chartType: ['pie']
    });
  this.loadData();
  this.updateService.updateChart$.subscribe(() => {
    
    this.loadData();
  });
  }


    
  

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
  this.dateForm.patchValue({
    start: undefined,
    end: undefined,
    chartType: 'pie'
  });

  this.loadData();
}  

}
