import { Component, input, signal, inject } from '@angular/core';
import { logout } from '../../auth/keycloak.service';
import { RouterLink } from '@angular/router';
import { DefaultService } from '../../api-client';
import { NgIf, NgFor } from '@angular/common';
import { ChartVisibilityService, Chart } from '../../services/chart-visibility.service';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { UploadResultDialogComponent } from '../upload-result-dialog/upload-result-dialog.component';


@Component({
  selector: 'app-header',
  imports: [RouterLink, NgIf, NgFor, MatDialogModule],
  templateUrl: './header.component.html',
  styleUrl: './header.component.scss'
})
export class HeaderComponent {
  title = signal('Security Event Detection');
  user = input('User');
  showDashboard1Menu = false;
  
  // Chart configuration
  charts: Chart[] = [];
  
  private defaultService = inject(DefaultService);
  private chartVisibilityService = inject(ChartVisibilityService);
  private dialog = inject(MatDialog);
  
  constructor() {
    // Initialize charts from the service
    this.charts = this.chartVisibilityService.getAllCharts();
    
    // Manuell sicherstellen, dass Chart 6 existiert
    if (!this.charts.some(chart => chart.id === 'chart6')) {
      this.chartVisibilityService.addChart({
        id: 'chart6',
        name: 'Diagramm 6',
        visible: true
      });
      // Charts neu laden
      this.charts = this.chartVisibilityService.getAllCharts();
    }
    
    // Subscribe to chart changes
    this.chartVisibilityService.charts$.subscribe(updatedCharts => {
      this.charts = updatedCharts;
      console.log('Charts im Header aktualisiert:', this.charts); // Debug-Ausgabe
    });

    
  }
  
  logout() {
    logout();
  }
  
  // Toggle chart visibility
  toggleChart(chartId: string) {
    this.chartVisibilityService.toggleChartVisibility(chartId);
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
    // Sucht das Datei-Input-Element im DOM
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    
    // Wenn das Input-Element gefunden wurde, simuliert einen Klick darauf, um den Dateiauswahldialog zu öffnen
    if (fileInput) {
      fileInput.click();
    }
  }
}