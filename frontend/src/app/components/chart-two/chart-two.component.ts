import { Component, inject, ViewChild, ElementRef } from '@angular/core';
import { ChartModule } from 'primeng/chart';
import { CommonModule } from '@angular/common';
import { DefaultService } from '../../api-client';
import { FormBuilder, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { ChartUpdateService } from '../../services/chart-update.service';

@Component({
  selector: 'app-chart-two',
  standalone: true,
  imports: [CommonModule, ChartModule, ReactiveFormsModule],
  templateUrl: './chart-two.component.html',
  styleUrl: './chart-two.component.scss'
})
export class ChartTwoComponent {
  @ViewChild('chart') chart: any; // Referenz zum Chart-Element
  
  private defaultService = inject(DefaultService);
  private updateService = inject(ChartUpdateService)
  private fb = inject(FormBuilder);
  
  // LocalStorage Keys
  private readonly COLOR_SCHEME_KEY = 'chart-two-color-scheme';
  private readonly CHART_SETTINGS_KEY = 'chart-two-settings';
  
  showSettings = false;
  dateForm!: FormGroup;
  hasData = false;
  chartVisible = true; // Für Chart-Neuzeichnung
  
  colorSchemes = [
    {
      name: 'Standard',
      colors: ['#F94144', '#F3722C', '#F8961E', '#F9844A', '#F9C74F', '#90BE6D', '#43AA8B', '#4D908E', '#577590', '#277DA1']
    },
    {
      name: 'Blues',
      colors: ['#08519c', '#3182bd', '#6baed6', '#9ecae1', '#c6dbef', '#deebf7', '#f7fbff', '#08306b', '#2171b5', '#4292c6']
    },
    {
      name: 'Reds',
      colors: ['#a50f15', '#de2d26', '#fb6a4a', '#fc9272', '#fcbba1', '#fee0d2', '#fff5f0', '#67000d', '#cb181d', '#ef3b2c']
    },
    {
      name: 'Greens',
      colors: ['#00441b', '#006d2c', '#238b45', '#41ab5d', '#74c476', '#a1d99b', '#c7e9c0', '#e5f5e0', '#f7fcf5', '#31a354']
    },
    {
      name: 'Rainbow',
      colors: ['#ff0000', '#ff8000', '#ffff00', '#80ff00', '#00ff00', '#00ff80', '#00ffff', '#0080ff', '#0000ff', '#8000ff']
    },
    {
      name: 'Pastel',
      colors: ['#ffb3ba', '#ffdfba', '#ffffba', '#baffc9', '#bae1ff', '#e0bbe4', '#ffc8a2', '#d4a4eb', '#a4c2f4', '#c4e17f']
    }
  ];
  
  currentColorScheme = 0;
  
  data: any = {
    labels: [],
    datasets: [{
      label: 'Login-Versuche pro IP',
      data: [],
      backgroundColor: ['#F94144', '#F3722C', '#F8961E', '#F9844A', '#F9C74F', '#90BE6D', '#43AA8B', '#4D908E', '#577590', '#277DA1']
    }]
  };

  options: any = {};

  ngOnInit(): void {
    // Gespeicherte Einstellungen laden
    this.loadSettingsFromStorage();
    
    this.dateForm = this.fb.group({
      start: [null],
      end: [null],
      chartType: ['pie']
    });
    
    // Initiale Options setzen
    this.updateChartOptions();
    
    // Chart-Typ Änderung überwachen und Chart zerstören
    this.dateForm.get('chartType')?.valueChanges.subscribe((newType) => {
      this.updateChartOptions();
      this.refreshChart();
      this.saveSettingsToStorage();
    });
    
    this.loadData();
    this.updateService.updateChart$.subscribe(() => {
      this.loadData();
    });
  }

  /**
   * Lädt die gespeicherten Einstellungen aus dem localStorage
   */
  private loadSettingsFromStorage(): void {
    try {
      // Farbschema laden
      const savedColorScheme = localStorage.getItem(this.COLOR_SCHEME_KEY);
      if (savedColorScheme !== null) {
        const colorSchemeIndex = parseInt(savedColorScheme, 10);
        if (colorSchemeIndex >= 0 && colorSchemeIndex < this.colorSchemes.length) {
          this.currentColorScheme = colorSchemeIndex;
        }
      }

      // Andere Chart-Einstellungen laden
      const savedSettings = localStorage.getItem(this.CHART_SETTINGS_KEY);
      if (savedSettings) {
        const settings = JSON.parse(savedSettings);
        // Hier können weitere Einstellungen geladen werden
        console.log('Geladene Einstellungen:', settings);
      }
    } catch (error) {
      console.warn('Fehler beim Laden der Einstellungen aus localStorage:', error);
      // Fallback auf Standardwerte
      this.currentColorScheme = 0;
    }
  }

  /**
   * Speichert die aktuellen Einstellungen im localStorage
   */
  private saveSettingsToStorage(): void {
    try {
      // Farbschema speichern
      localStorage.setItem(this.COLOR_SCHEME_KEY, this.currentColorScheme.toString());

      // Andere Chart-Einstellungen speichern
      const settings = {
        colorScheme: this.currentColorScheme,
        chartType: this.dateForm?.get('chartType')?.value || 'pie',
        lastUpdated: new Date().toISOString()
      };
      localStorage.setItem(this.CHART_SETTINGS_KEY, JSON.stringify(settings));
    } catch (error) {
      console.warn('Fehler beim Speichern der Einstellungen in localStorage:', error);
    }
  }

  loadData(start?: string, end?: string) {
    const observe = 'body';
    const reportProgress = false;
    const call = (start && end)
      ? this.defaultService.logfilesProcessedLoginsGet(start, end, observe, reportProgress)
      : this.defaultService.logfilesProcessedLoginsGet();
    
    call.subscribe((logins: any[]) => {
      const ipCountMap: { [ip: string]: number } = {};
      logins.forEach(entry => {
        if (entry.result === 'failed') {
          const ip = entry.src_ip_address;
          ipCountMap[ip] = (ipCountMap[ip] || 0) + 1;
        }
      });
      
      if(Object.values(ipCountMap).length === 0){
        this.hasData = false;
      } else {
        this.hasData = true;
      }
      
      this.data = {
        labels: Object.keys(ipCountMap),
        datasets: [{
          label: 'failed logins by IP',
          data: Object.values(ipCountMap),
          backgroundColor: this.getBackgroundColors(Object.keys(ipCountMap).length)
        }]
      };
      
      // Chart nach Datenänderung neu zeichnen
      this.refreshChart();
    });
  }

  private getBackgroundColors(count: number): string[] {
    const colors = this.colorSchemes[this.currentColorScheme].colors;
    return colors.slice(0, count);
  }

  private refreshChart(): void {
    // Chart komplett zerstören und neu erstellen
    this.chartVisible = false;
    
    // Längeres Timeout für vollständige Zerstörung
    setTimeout(() => {
      this.chartVisible = true;
    }, 100);
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
    this.saveSettingsToStorage();
  }

  onReset() {
    this.dateForm.patchValue({
      start: undefined,
      end: undefined,
      chartType: 'pie'
    });
    
    this.currentColorScheme = 0;
    this.loadData();
    this.saveSettingsToStorage();
    this.updateChartColors();
  }

  private getScalesConfig(): any {
    const chartType = this.dateForm?.get('chartType')?.value || 'pie';
    
    if (chartType === 'bar') {
      return {
        y: {
          beginAtZero: true,
          ticks: {
            font: {
              size: 12
            }
          }
        },
        x: {
          ticks: {
            font: {
              size: 12
            }
          }
        }
      };
    }
    return {};
  }

  // Options aktualisieren basierend auf Chart-Typ
  private updateChartOptions(): void {
    this.options = {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: {
          position: 'bottom',
          align: 'center',
          labels: {
            boxWidth: 25,
            padding: 15,
            font: {
              size: 20
            }
          }
        },
        tooltip: {
          backgroundColor: 'rgba(0, 0, 0, 0.7)',
          padding: 10,
          titleFont: {
            size: 14
          },
          bodyFont: {
            size: 13
          }
        }
      },
      scales: this.getScalesConfig()
    };
  }

  onColorSchemeChange(event: any): void {
    this.currentColorScheme = parseInt(event.target.value);
    this.updateChartColors();
    this.saveSettingsToStorage();
  }

  private updateChartColors(): void {
    if (this.data && this.data.datasets && this.data.datasets[0]) {
      this.data.datasets[0].backgroundColor = this.getBackgroundColors(this.data.labels.length);
      this.refreshChart();
    }
  }

  clearStoredSettings(): void {
    try {
      localStorage.removeItem(this.COLOR_SCHEME_KEY);
      localStorage.removeItem(this.CHART_SETTINGS_KEY);
      console.log('Gespeicherte Einstellungen wurden gelöscht');
    } catch (error) {
      console.warn('Fehler beim Löschen der gespeicherten Einstellungen:', error);
    }
  }
}