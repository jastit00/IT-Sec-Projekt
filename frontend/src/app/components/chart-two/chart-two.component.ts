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
      backgroundColor: [
        "hsl(0, 100%, 50%)",
        "hsl(18.18, 100%, 50%)",
        "hsl(36.36, 100%, 50%)",
        "hsl(54.54, 100%, 50%)",
        "hsl(72.72, 100%, 50%)",
        "hsl(90.9, 100%, 50%)",
        "hsl(109.09, 100%, 50%)",
        "hsl(127.27, 100%, 50%)",
        "hsl(145.45, 100%, 50%)",
        "hsl(163.64, 100%, 50%)",
        "hsl(181.82, 100%, 50%)",
        "hsl(200, 100%, 50%)",
        "hsl(218.18, 100%, 50%)",
        "hsl(236.36, 100%, 50%)",
        "hsl(254.54, 100%, 50%)",
        "hsl(272.72, 100%, 50%)",
        "hsl(290.9, 100%, 50%)",
        "hsl(309.09, 100%, 50%)",
        "hsl(327.27, 100%, 50%)",
        "hsl(345.45, 100%, 50%)"
      ]
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