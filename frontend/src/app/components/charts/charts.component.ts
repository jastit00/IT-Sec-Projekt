import { Component } from '@angular/core';
import { ChartModule } from 'primeng/chart';  
import { CommonModule } from '@angular/common';  

@Component({
  selector: 'app-charts',
  standalone: true,
  imports: [CommonModule, ChartModule],
  templateUrl: './charts.component.html',
  styleUrls: ['./charts.component.scss']
})
export class ChartsComponent {
  data = {
    labels: ['Red', 'Blue', 'Yellow', 'Green', 'Purple'],
    datasets: [{
      data: [300, 50, 100, 75, 200],
      backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
    }]
  };

  options = {
    responsive: true,
    maintainAspectRatio: false
  };
data1: any;
options1: any;
data2: any;
options2: any;
data3: any;
options3: any;
data4: any;
options4: any;
}
