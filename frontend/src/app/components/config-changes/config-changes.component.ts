import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatTableModule } from '@angular/material/table';
import { DefaultService } from '../../api-client';

@Component({
  selector: 'app-config-changes',
  standalone: true,
  imports: [CommonModule, MatTableModule],
  templateUrl: './config-changes.component.html',
  styleUrl: './config-changes.component.scss'
})
export class ConfigChangesComponent implements OnInit {
  private defaultService = inject(DefaultService);

  logEntries: any[] = [];
  displayedColumns: string[] = [];
  dataSource: any[] = [];

  ngOnInit() {
    this.defaultService.logfilesConfigChangesGet().subscribe({
      next: (data) => {
        this.logEntries = data;
        this.displayedColumns = Object.keys(data[0] || {}); // Fallback für leeres Array
        this.dataSource = data;
      },
      error: (err) => {
        console.error('API Fehler bei Config Logs:', err);
      }
    });
  }

  onSettingsClick() {
    console.log('Test Click');
  }
}


  