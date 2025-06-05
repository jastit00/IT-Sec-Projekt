import { OnInit, ViewChild, Component } from '@angular/core';
import { FormBuilder, FormGroup } from '@angular/forms';
import { defaultChartOptions } from '../charts/chart-options';

@Component({
  selector: 'app-base-chart',
  template: '',
})
export abstract class BaseChartComponent implements OnInit {
  @ViewChild('chart') chart: any;

  showSettings = false;
  chartVisible = true;
  hasData = false;

  showTargetIpSelect = false;
  availableDstIps: string[] = [];

  data: any = { labels: [], datasets: [] };
  options: any = defaultChartOptions;

  dateForm!: FormGroup;
  currentColorScheme = 0;

  // Farbschemas
  colorSchemes = [
    { name: 'Standard', colors: ['#F94144', '#F3722C', '#F8961E', '#F9844A', '#F9C74F', '#90BE6D', '#43AA8B', '#4D908E', '#577590', '#277DA1'] },
    { name: 'Blues', colors: ['#08519c', '#3182bd', '#6baed6', '#9ecae1', '#c6dbef', '#deebf7', '#f7fbff', '#08306b', '#2171b5', '#4292c6'] },
    { name: 'Reds', colors: ['#a50f15', '#de2d26', '#fb6a4a', '#fc9272', '#fcbba1', '#fee0d2', '#fff5f0', '#67000d', '#cb181d', '#ef3b2c'] },
    { name: 'Greens', colors: ['#00441b', '#006d2c', '#238b45', '#41ab5d', '#74c476', '#a1d99b', '#c7e9c0', '#e5f5e0', '#f7fcf5', '#31a354'] },
    { name: 'Rainbow', colors: ['#ff0000', '#ff8000', '#ffff00', '#80ff00', '#00ff00', '#00ff80', '#00ffff', '#0080ff', '#0000ff', '#8000ff'] },
    { name: 'Pastel', colors: ['#ffb3ba', '#ffdfba', '#ffffba', '#baffc9', '#bae1ff', '#e0bbe4', '#ffc8a2', '#d4a4eb', '#a4c2f4', '#c4e17f']}
  ];

  protected abstract defaultService: any;
  protected abstract fb: FormBuilder;
  protected abstract updateService: any;

  private readonly COLOR_SCHEME_KEY = 'chart-two-color-scheme';
  private readonly CHART_SETTINGS_KEY = 'chart-two-settings';

  ngOnInit(): void {
    this.dateForm = this.fb.group({
      start: [null],
      end: [null],
      chartType: ['pie']
    });

    this.loadSettingsFromStorage();
    this.updateChartOptions();

    this.dateForm.get('chartType')?.valueChanges.subscribe(() => {
      this.updateChartOptions();
      this.refreshChart();
      this.saveSettingsToStorage();
    });

    this.loadData();

    this.updateService.updateChart$.subscribe(() => {
      this.loadData();
    })
    
  }

  

  protected loadSettingsFromStorage(): void {
    try {
      const savedColorScheme = localStorage.getItem(this.COLOR_SCHEME_KEY);
      if (savedColorScheme !== null) {
        const index = parseInt(savedColorScheme, 10);
        if (index >= 0 && index < this.colorSchemes.length) {
          this.currentColorScheme = index;
        }
      }

      const savedSettings = localStorage.getItem(this.CHART_SETTINGS_KEY);
      if (savedSettings) {
        const settings = JSON.parse(savedSettings);
        console.log('Geladene Einstellungen:', settings);
        
      }
    } catch {
      this.currentColorScheme = 0;
    }
  }

  protected saveSettingsToStorage(): void {
    try {
      localStorage.setItem(this.COLOR_SCHEME_KEY, this.currentColorScheme.toString());
      const settings = {
        colorScheme: this.currentColorScheme,
        chartType: this.dateForm.get('chartType')?.value || 'pie',
        lastUpdated: new Date().toISOString()
      };
      localStorage.setItem(this.CHART_SETTINGS_KEY, JSON.stringify(settings));
    } catch {}
  }

  protected getBackgroundColors(count: number): string[] {
    const colors = this.colorSchemes[this.currentColorScheme].colors;
    return colors.slice(0, count);
  }

  protected getScalesConfig(chartType: string): any {
    if (chartType === 'bar') {
      return {
        y: { beginAtZero: true, ticks: { font: { size: 12 } } },
        x: { ticks: { font: { size: 12 } } }
      };
    }
    return {};
  }

  protected updateChartOptions(): void {
    const chartType = this.dateForm.get('chartType')?.value || 'pie';
    this.options = defaultChartOptions;
    this.options.scales = this.getScalesConfig(chartType)
  }

  refreshChart(): void {
    this.chartVisible = false;
    setTimeout(() => (this.chartVisible = true), 100);
  }

  onSettingsClick(): void {
    this.showSettings = !this.showSettings;
  }

  onApply(): void {
    const startDate = this.dateForm.get('start')?.value;
    const endDate = this.dateForm.get('end')?.value;
    const start = startDate ? new Date(startDate).toISOString() : undefined;
    const end = endDate ? new Date(endDate).toISOString() : undefined;

    this.loadData(start, end);
    this.showSettings = false;
    this.saveSettingsToStorage();
  }

  onReset(): void {
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

  onColorSchemeChange(event: any): void {
    this.currentColorScheme = parseInt(event.target.value);
    this.updateChartColors();
    this.saveSettingsToStorage();
  }

  updateChartColors(): void {
    if (this.data && this.data.datasets && this.data.datasets[0]) {
      this.data.datasets[0].backgroundColor = this.getBackgroundColors(this.data.labels.length);
      this.refreshChart();
    }
  }
  abstract loadData(start?: string, end?: string): void;
}