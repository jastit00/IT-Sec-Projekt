import { Component, OnInit, inject } from '@angular/core';

import { MatTableModule } from '@angular/material/table';
import { DefaultService } from '../../../api-client';
import { FormBuilder, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { ChartUpdateService } from '../../../services/chart-update.service';

@Component({
  selector: 'app-config-changes',
  standalone: true,
  imports: [MatTableModule, ReactiveFormsModule],
  templateUrl: './config-changes.component.html',
  styleUrl: './config-changes.component.scss'
})
export class ConfigChangesComponent implements OnInit {
  private defaultService = inject(DefaultService);
  private updateService = inject(ChartUpdateService);
  private fb = inject(FormBuilder);

  showSettings = false;
  dateForm!: FormGroup;
  hasData = false;


  displayedColumns: string[] = ['id', 'timestamp', 'table', 'action', 'user', 'result', 'description'];
  dataSource: any[] = [];

  ngOnInit(): void {
  
  this.dateForm = this.fb.group({
      start: [null],
      end: [null],
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
    

    ? this.defaultService.logfilesConfigChangesGet(start, end, observe, reportProgress)
    : this.defaultService.logfilesConfigChangesGet();


    call.subscribe((entries: any[]) => {

      if(entries.length ===0){
        this.hasData = false;
      }
      else {
        this.hasData = true;
      }

      this.dataSource = entries.map((entry) => ({
        id: entry.id,
        timestamp: new Date(entry.timestamp).toLocaleString(), 
        table: entry.table,
        action: entry.action,
        user: entry.terminal,
        result: entry.result,
        description: `Key: ${entry.key}, Value: ${entry.value}, Condition: ${entry.condition || '—'}`
      }));
    });
  }

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

  