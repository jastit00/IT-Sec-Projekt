import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatTableModule } from '@angular/material/table';
import { DefaultService } from '../../api-client';
import { ChartUpdateService } from '../../services/chart-update.service';

@Component({
  selector: 'app-config-changes',
  standalone: true,
  imports: [CommonModule, MatTableModule],
  templateUrl: './config-changes.component.html',
  styleUrl: './config-changes.component.scss'
})
export class ConfigChangesComponent implements OnInit {
  private defaultService = inject(DefaultService);
  private updateService = inject(ChartUpdateService)


  displayedColumns: string[] = ['id', 'timestamp', 'table', 'action', 'user', 'result', 'description'];
  dataSource: any[] = [];

  ngOnInit(): void {
  
  this.loadData();
  this.updateService.updateChart$.subscribe(() => {
    this.loadData();
  });

  }

 loadData() {
    this.defaultService.logfilesConfigChangesGet().subscribe((entries: any[]) => {
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
    console.log('Test Click');
  }
}


  