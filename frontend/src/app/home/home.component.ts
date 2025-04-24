import { Component } from '@angular/core';
import { ChartOneComponent } from '../components/chart-one/chart-one.component';
import { ChartTwoComponent } from '../components/chart-two/chart-two.component';
import { ChartThreeComponent } from '../components/chart-three/chart-three.component';
import { ChartFourComponent } from '../components/chart-four/chart-four.component';

@Component({
  selector: 'app-home',
  imports: [ChartOneComponent, ChartTwoComponent, ChartThreeComponent, ChartFourComponent],
  templateUrl: './home.component.html',
  styleUrl: './home.component.scss'
})
export class HomeComponent {

}
