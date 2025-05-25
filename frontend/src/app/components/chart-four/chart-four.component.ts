import { Component, inject, Input, OnInit, SimpleChanges } from '@angular/core';
import { ChartModule } from 'primeng/chart';
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../api-client';
import { FormBuilder, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { ChartUpdateService } from '../../services/chart-update.service';

@Component({
  selector: 'app-chart-four',
  standalone: true,
  imports: [CommonModule, ChartModule, ReactiveFormsModule],
  templateUrl: './chart-four.component.html',
  styleUrls: ['./chart-four.component.scss']
})

export class ChartFourComponent implements OnInit {
  private defaultService = inject(DefaultService);
  private updateService = inject(ChartUpdateService);
  private fb = inject(FormBuilder);

 showSettings = false;
 dateForm!: FormGroup;
 hasData = false;

  data: any = {
    labels: [],
    datasets: [{
      label: 'number of incidents',
      data: [],
      backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
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
  
    const call = (start && end)
    

    ? this.defaultService.logfilesIncidentsGet(start, end, observe, reportProgress)
    : this.defaultService.logfilesIncidentsGet();


    call.subscribe((logins: any[]) => {
      const typeCountMap: { [type: string]: number } = {};
  
      logins.forEach(entry => {
        const type = entry.incident_type;
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
          label: 'number of incidents',
          data: Object.values(typeCountMap),
          backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
          
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
