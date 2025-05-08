import { Component, inject, Input, OnInit, SimpleChanges } from '@angular/core';
import { ChartModule } from 'primeng/chart';
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../api-client';
import { FormBuilder, FormGroup } from '@angular/forms';

@Component({
  selector: 'app-chart-one',
  standalone: true,
  imports: [CommonModule, ChartModule],
  templateUrl: './chart-one.component.html',
  styleUrls: ['./chart-one.component.scss']
})

export class ChartOneComponent implements OnInit {

  private defaultService = inject(DefaultService);
  private fb = inject(FormBuilder);

  @Input() data: any = {
    labels: [],
    datasets: [{
      label: 'Login-Versuche pro IP',
      data: [],
      backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
    }]
  };
  
  chartForm: FormGroup;

  constructor() {
    this.chartForm = this.fb.group({
      data: this.data
    });
  }

  ngOnInit(): void {
    this.defaultService.logfilesProcessedLoginsGet().subscribe((logins: any[]) => {
      const ipCountMap: { [ip: string]: number } = {};
  
      logins.forEach(entry => {
        const ip = entry.ip_address;
        ipCountMap[ip] = (ipCountMap[ip] || 0) + 1;
      });

      this.chartForm.patchValue({
        data: {
          labels: Object.keys(ipCountMap),
          datasets: [{
            label: 'Login-Versuche pro IP',
            data: Object.values(ipCountMap),
            backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
          }]
        }
      });
    });
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['data']) {
      this.chartForm.patchValue({
        data: changes['data'].currentValue
      });
    }
  }

  options = {
    responsive: true,
    maintainAspectRatio: false,
    scale: {
      ticks: {
        beginAtZero: true,
        max: 100, 
        stepSize: 20
      }
    },
    plugins: {
      legend: {
        position: 'top', 
        labels: {
          font: {
            size: 14
          }
        }
      },
    },
    layout: {
      padding: {
        top: 0,  
        right: 0,
        bottom: 0,
        left: 0
      }
    }
  };
onSettingsClick() {
    console.log('Test Click');
  }
  

}
