import { Component, inject } from '@angular/core';
import { ChartModule } from 'primeng/chart';  
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../api-client';
import { FormBuilder, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { ChartUpdateService } from '../../services/chart-update.service';

@Component({
  selector: 'app-chart-two',
  standalone: true,
  imports: [CommonModule, ChartModule, ReactiveFormsModule],
  templateUrl: './chart-two.component.html',
  styleUrl: './chart-two.component.scss'
})
export class ChartTwoComponent {
  private defaultService = inject(DefaultService);
  private updateService = inject(ChartUpdateService)
  private fb = inject(FormBuilder);
  
  showSettings = false;
  dateForm!: FormGroup;
  hasData = false;


  data: any = {
    labels: [],
    datasets: [{
      label: 'Login-Versuche pro IP',
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
  
    const call = (start && end)
    

    ? this.defaultService.logfilesProcessedLoginsGet(start, end, observe, reportProgress)
    : this.defaultService.logfilesProcessedLoginsGet();


    call.subscribe((logins: any[]) => {
      const ipCountMap: { [ip: string]: number } = {};
  
      logins.forEach(entry => {
        if (entry.result === 'failed') {
        const ip = entry.src_ip_address;
        ipCountMap[ip] = (ipCountMap[ip] || 0) + 1;
        }
      });

      if(Object.values(ipCountMap).length ===0){
        this.hasData = false;
      }
      else {
        this.hasData = true;
      }
  
      this.data = {
        labels: Object.keys(ipCountMap),
        datasets: [{
          label: 'failed logins by IP',
          data: Object.values(ipCountMap),
          
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
    chartType: 'bar'
  });

  this.loadData();
}  

}