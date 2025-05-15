import { Component, input, signal, inject, ViewChild, ElementRef } from '@angular/core';
import { logout } from '../../auth/keycloak.service';
import { RouterLink } from '@angular/router';
import { DefaultService } from '../../api-client';
import { NgIf, NgFor } from '@angular/common';
import { ChartVisibilityService, Chart } from '../../services/chart-visibility.service';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { UploadResultDialogComponent } from '../upload-result-dialog/upload-result-dialog.component';
import { BadgeModule } from 'primeng/badge';
import { EventService } from '../../services/event-service';

@Component({
  selector: 'app-header',
  imports: [RouterLink, NgIf, NgFor, MatDialogModule, BadgeModule],
  templateUrl: './header.component.html',
  styleUrl: './header.component.scss'
})
export class HeaderComponent {
  title = signal('Security Event Detection');
  user = input('User');
  showDashboard1Menu = false;
  // Chart configuration
  charts: Chart[] = [];
  // Flag to track if max charts are reached
  isMaxChartsReached = false;
  
  @ViewChild('fileInput') fileInput!: ElementRef<HTMLInputElement>;
  
  private defaultService = inject(DefaultService);
  private chartVisibilityService = inject(ChartVisibilityService);
  private dialog = inject(MatDialog);
  private eventService = inject(EventService);

  constructor() {
    // Initialize charts from the service
    this.charts = this.chartVisibilityService.getAllCharts();
    
    // Check if max charts are reached initially
    this.isMaxChartsReached = this.chartVisibilityService.isMaxChartsReached();
    
    // Manuell sicherstellen, dass Chart 6 existiert
    if (!this.charts.some(chart => chart.id === 'chart6')) {
      this.chartVisibilityService.addChart({
        id: 'chart6',
        name: 'Diagramm 6',
        visible: false
      });
      // Charts neu laden
      this.charts = this.chartVisibilityService.getAllCharts();
    }
    
    // Subscribe to chart changes
    this.chartVisibilityService.charts$.subscribe(updatedCharts => {
      this.charts = updatedCharts;
      // Update max charts reached status
      this.isMaxChartsReached = this.chartVisibilityService.isMaxChartsReached();
      console.log('Charts im Header aktualisiert:', this.charts, 'Max reached:', this.isMaxChartsReached);
    });
  }

  // Get count of critical events
  getCriticalEventsCount(): number {
    return this.eventService.events.filter(event => event.status === 'Kritisch').length;
  }
  
  // Check if there are any critical events
  hasCriticalEvents(): boolean {
    return this.getCriticalEventsCount() > 0;
  }

  logout() {
    logout();
  }

  // Toggle chart visibility
  toggleChart(chartId: string) {
    const result = this.chartVisibilityService.toggleChartVisibility(chartId);
    if (!result) {
      // Optional: Add notification or show message when toggle failed
      console.log('Could not toggle chart - maximum visible charts reached');
    }
  }

  // Debug-Methode: Lokalen Speicher zurücksetzen
  resetLocalStorage() {
    localStorage.removeItem('chartConfiguration');
    this.chartVisibilityService.resetToDefaults();
    console.log('LocalStorage zurückgesetzt');
  }

  // Methode wird aufgerufen wenn Datei ausgewählt wird
  onFileSelected($event: Event) {
    // Die Dateien aus dem Event extrahieren
    const input = $event.target as HTMLInputElement;
    const files = input.files;
    if (files && files.length > 0) {
      const now = new Date().toISOString();
      this.defaultService.logfilesPost(files[0], "InputFirewall", "currentUser", now).subscribe({
        next: (result) => {
          this.dialog.open(UploadResultDialogComponent, {
            data: result
          });
        },
        error: (err) => {
          // Falls der Server ein JSON mit "status" und "message" liefert
          const serverError = err.error?.status === 'error'
            ? err.error
            : { status: 'error', message: 'Unbekannter Fehler beim Upload.' };
          this.dialog.open(UploadResultDialogComponent, {
            data: serverError
          });
        }
      });
    }
  }

  // Methode, die den Dateiauswahldialog öffnet
  openFileUpload() {
    if (this.fileInput) {
      this.fileInput.nativeElement.click();
    } else {
      // Fallback if ViewChild isn't available yet
      const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
      if (fileInput) {
        fileInput.click();
      }
    }
  }
}