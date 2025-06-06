import { Component, signal, inject, ViewChild, ElementRef, OnInit } from '@angular/core';
import { keycloak, logout } from '../../auth/keycloak.service';
import { RouterLink } from '@angular/router';
import { DefaultService } from '../../api-client';

import { ChartVisibilityService, Chart } from '../../services/chart-visibility.service';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatIconModule } from '@angular/material/icon';
import { UploadResultDialogComponent } from '../upload-result-dialog/upload-result-dialog.component';
import { ConfigpopupComponent } from '../configpopup/configpopup.component';
import { BadgeModule } from 'primeng/badge';
import { EventService } from '../../services/event-service';
import { ChartUpdateService } from '../../services/chart-update.service';
import { ReactiveFormsModule, FormGroup, FormBuilder, Validators  } from '@angular/forms';
import { PresetIdService } from '../../services/preset-id.service';
import { Subscription } from 'rxjs';


@Component({
  selector: 'app-header',
  imports: [RouterLink, MatDialogModule, BadgeModule, ReactiveFormsModule, MatTooltipModule, MatIconModule],
  templateUrl: './header.component.html',
  styleUrl: './header.component.scss'
})

export class HeaderComponent implements OnInit {
  title = signal('Security Event Detection');
  username = signal('User'); // Default value until Keycloak data is loaded
  showDashboard1Menu = false;
  showDashboard2Menu = false;
  showDashboard3Menu = false;

  charts: Chart[] = [];
  isMaxChartsReached = false;
  
  @ViewChild('fileInput') fileInput!: ElementRef<HTMLInputElement>;
  
  private defaultService = inject(DefaultService);
  private chartVisibilityService = inject(ChartVisibilityService);
  private dialog = inject(MatDialog);
  private eventService = inject(EventService);
  private updateService = inject(ChartUpdateService);
  private fb = inject(FormBuilder);

  showSettingsForm = false;
  settingsForm!: FormGroup;
  visibilitySubscription!: Subscription;

  constructor(private presetIdService: PresetIdService) {

    this.charts = this.chartVisibilityService.getAllCharts();
    this.isMaxChartsReached = this.chartVisibilityService.isMaxChartsReached();
    
    this.visibilitySubscription = this.chartVisibilityService.charts$.subscribe(updatedCharts => {
      this.charts = updatedCharts;
      this.isMaxChartsReached = this.chartVisibilityService.isMaxChartsReached();
      console.log('Charts refreshed:', this.charts, 'Max reached:', this.isMaxChartsReached);
    });
  }

  ngOnInit(): void {
    this.initUsername();
    console.log('HeaderComponent initialized, attempting to get Keycloak username');
    this.settingsForm = this.fb.group({
      brute_force: this.fb.group({
        attempt_threshold: [10, [Validators.required, Validators.min(1)]],
        time_delta: [120, [Validators.required, Validators.min(1)]],
        repeat_threshold: [600, [Validators.required, Validators.min(1)]],
      }),
      dos: this.fb.group({
        packet_threshold: [100, [Validators.required, Validators.min(1)]],
        time_delta: [10, [Validators.required, Validators.min(1)]],
        repeat_threshold: [120, [Validators.required, Validators.min(1)]],
      }),
      ddos: this.fb.group({
        packet_threshold: [10, [Validators.required, Validators.min(1)]],
        time_delta: [2, [Validators.required, Validators.min(1)]],
        repeat_threshold: [60, [Validators.required, Validators.min(1)]],
        min_sources: [2, [Validators.required, Validators.min(1)]],
      }),
    });
  }

  ngOnDestroy(): void {
    if (this.visibilitySubscription) {
      this.visibilitySubscription.unsubscribe();
    }
  }

  setDashboard(id: string) {
    this.presetIdService.setPresetId(id);
    console.log('PresetId gesetzt auf:', id);
  }

  // Initialize username from Keycloak
  private initUsername() {
    console.log('Initializing username, Keycloak authenticated:', keycloak.authenticated);
    if (keycloak.authenticated) {
      try {
        // Safely access token information
        if (keycloak.idTokenParsed) {
          const tokenInfo = keycloak.idTokenParsed as any;
          const preferredUsername = tokenInfo.preferred_username;
          const name = tokenInfo.name;
          
          // Use preferred_username, full name, or just 'User' if nothing is available
          this.username.set(preferredUsername || name || 'User');
          console.log('Keycloak username set:', this.username());
          console.log('Keycloak username set:', keycloak.token);
          //updatefunction(this.username());
        } else {
          // If token isn't parsed yet, get username directly from keycloak instance
          keycloak.loadUserProfile().then(profile => {
            this.username.set(profile.username || 'User');
            console.log('Username loaded from profile:', profile.username);
          }).catch(error => {
            console.error('Failed to load user profile:', error);
            this.username.set('User');
          });
        }
      } catch (error) {
        console.error('Error accessing Keycloak token:', error);
        this.username.set('User');
      }
    } else {
      this.username.set('User');
      console.log('Keycloak not authenticated, using default username');
    }
  }

  getCriticalEventsCount(): number {
    return this.eventService.events.filter(event => event.status === 'Critical').length;
  }
  
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

  // Debug method: Reset local storage
  resetLocalStorage() {
    localStorage.removeItem('chartConfiguration');
    this.chartVisibilityService.resetToDefaults();
    console.log('LocalStorage zurückgesetzt');
  }

  onFileSelected($event: Event) {
    const input = $event.target as HTMLInputElement;
    const files = input.files;
    if (files && files.length > 0) {
      // Get username safely
      let currentUsername = 'unknown';
      if (keycloak.authenticated) {
        try {
          const tokenInfo = keycloak.idTokenParsed as any;
          currentUsername = tokenInfo?.preferred_username || 'unknown';
        } catch (error) {
          console.error('Error accessing token information:', error);
        }
      }
      
      const now = new Date().toISOString();
      this.defaultService.logfilesPost(files[0], "InputFirewall", currentUsername, now).subscribe({
        next: (result) => {
          this.dialog.open(UploadResultDialogComponent, {
            data: result
            
          });
            this.updateService.triggerChartUpdate();

        },
        error: (err) => {
          // If server returns JSON with "status" and "message"
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

  onSettingsClick(){
    this.showSettingsForm = !this.showSettingsForm;
  }

  submitSettings() {
    if (this.settingsForm.valid){
    this.defaultService.incidentsConfigPost(this.settingsForm.value).subscribe({
      next: response => {
        this.dialog.open(ConfigpopupComponent, {
          data: response
        })

        if (response.result) {
          this.settingsForm.patchValue({
            brute_force: {
              attempt_threshold: response.config?.brute_force?.attempt_threshold,
              time_delta: response.config?.brute_force?.time_delta,
              repeat_threshold: response.config?.brute_force?.repeat_threshold,
            },
            dos: {
              packet_threshold: response.config?.dos?.packet_threshold,
              time_delta: response.config?.dos?.time_delta,
              repeat_threshold: response.config?.dos?.repeat_threshold,
            },
            ddos: {
              packet_threshold: response.config?.ddos?.packet_threshold,
              time_delta: response.config?.ddos?.time_delta,
              repeat_threshold: response.config?.ddos?.repeat_threshold,
              min_sources: response.config?.ddos?.min_sources,
            }
          });
        }
        this.showSettingsForm = false;
        this.updateService.triggerChartUpdate();
      },
      error: err => {
        console.error('Fehler beim Senden der Einstellungen:', err);
    }});
  }
  else {
    console.error('Not validated');
  }}
}
