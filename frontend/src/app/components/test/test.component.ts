import { Component } from '@angular/core';
import { MenubarModule } from 'primeng/menubar';  
import { CommonModule } from '@angular/common'; 

@Component({
  selector: 'app-test',
  standalone: true, 
  imports: [MenubarModule, CommonModule], 
  templateUrl: './test.component.html',
  styleUrls: ['./test.component.scss']
})
export class TestComponent {
  items = [
    {
      label: 'Dashboard',
      icon: 'pi pi-fw pi-cog',
      items: [
        { label: 'Individuelles Dashboard 1'}, //hier eventuell individuelle dashboards machen???
        { label: 'Individuelles Dashboard 2'},
        { label: 'Individuelles Dashboard 3'}
      ]
    }
  ];
}
