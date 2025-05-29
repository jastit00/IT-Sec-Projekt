import { Injectable, signal } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { PresetIdService } from './preset-id.service';

export interface Chart {
  id: string;
  name: string;
  visible: boolean;
}

@Injectable({
  providedIn: 'root'
})
export class ChartVisibilityService {

  private readonly MAX_VISIBLE_CHARTS = 4;

  private defaultCharts: Chart[] = [
    { id: 'chart1', name: 'Attempted Logins', visible: true },
    { id: 'chart2', name: 'Failed Logins', visible: true },
    { id: 'chart3', name: 'Forwarded Packets', visible: true },
    { id: 'chart4', name: 'Incidents', visible: true },
    { id: 'chart5', name: 'DOS Packets', visible: true },
    { id: 'chart6', name: 'DDOS Packets', visible: false },
    { id: 'config-changes', name: 'Configuration Changes (Table)', visible: false },
    { id: 'chart8', name: 'Configuration Changes', visible: false }, // Default auf false gesetzt, da Max = 4
  ];

  private chartPresets: { [presetId: string]: Chart[] } = {};
  
  // BehaviorSubject to track chart visibility state
  private chartsSubject = new BehaviorSubject<Chart[]>(this.defaultCharts);
  
  // Observable that components can subscribe to
  public charts$: Observable<Chart[]> = this.chartsSubject.asObservable();

  constructor(private presetIdService: PresetIdService) {
    this.loadSavedConfiguration();
    this.presetIdService.presetId$.subscribe(() => {
      this.updateChartsForCurrentPreset();
    });
  }

  private get currentPresetId(): string {
    return this.presetIdService.getPresetId() || '1';
  }

  private updateChartsForCurrentPreset(): void {
    const presetId = this.currentPresetId;
    if (!this.chartPresets[presetId]) {
      this.chartPresets[presetId] = [...this.defaultCharts];
    } else {
      this.ensureAllDefaultChartsExist(presetId);
    }

    this.enforceMaxVisibleCharts();
    this.chartsSubject.next([...this.chartPresets[presetId]]);
  }

  private ensureAllDefaultChartsExist(presetId: string): void {
    this.defaultCharts.forEach(defaultChart => {
      if (!this.chartPresets[presetId].some(c => c.id === defaultChart.id)) {
        this.chartPresets[presetId].push({ ...defaultChart, visible: false });
      }
    });
  }

  toggleChartVisibility(id: string): boolean {
    const currentCharts = this.chartPresets[this.currentPresetId] || [...this.defaultCharts];
    const chart = currentCharts.find(c => c.id === id);
    if (!chart) return false;
    
    const visibleCount = this.getVisibleChartsCount();
    if (chart.visible) {
      chart.visible = false;
    } else {
      if (visibleCount >= this.MAX_VISIBLE_CHARTS) {
        console.warn(`Maximale Anzahl an Diagrammen (${this.MAX_VISIBLE_CHARTS}) erreicht.`);
        return false;
      }
      chart.visible = true;
    }

    this.saveConfiguration(currentCharts);
    this.chartsSubject.next([...currentCharts]);
    return true;
  }

  setChartVisibility(chartId: string, visibility: boolean): boolean {
    const charts = this.chartPresets[this.currentPresetId] || [...this.defaultCharts];
    const chart = charts.find(c => c.id === chartId);
    if (!chart) return false;

    if (visibility && !chart.visible && this.getVisibleChartsCount() >= this.MAX_VISIBLE_CHARTS) {
      console.warn(`Maximale Anzahl an Diagrammen (${this.MAX_VISIBLE_CHARTS}) erreicht.`);
      return false;
    }

    chart.visible = visibility;
    this.saveConfiguration(charts);
    this.chartsSubject.next([...charts]);
    return true;
  }

  getVisibleCharts(): string[] {
    const charts = this.chartPresets[this.currentPresetId] || [];
    return charts.filter(c => c.visible).map(c => c.id);
  }

  getVisibleChartsCount(): number {
    return this.getVisibleCharts().length;
  }

  isMaxChartsReached(): boolean {
    return this.getVisibleChartsCount() >= this.MAX_VISIBLE_CHARTS;
  }

  getAllCharts(): Chart[] {
    return this.chartPresets[this.currentPresetId] || this.chartPresets['1'];
  }

  //Add a new chart or update an existing one
  addChart(chart: Chart): boolean {
    const currentCharts = this.chartPresets[this.currentPresetId] || [...this.defaultCharts];
    const existingChartIndex = currentCharts.findIndex(c => c.id === chart.id);
    
    if (chart.visible && this.getVisibleChartsCount() >= this.MAX_VISIBLE_CHARTS) {
      chart.visible = false;
    }

    if (existingChartIndex >= 0) {
      currentCharts[existingChartIndex] = chart;
    } else {
      currentCharts.push(chart);
    }

    this.saveConfiguration(currentCharts);
    this.chartsSubject.next([...currentCharts]);
    return true;
  }

  resetToDefaults(): void {
    this.chartPresets[this.currentPresetId] = [...this.defaultCharts];
    this.enforceMaxVisibleCharts();
    this.saveConfiguration(this.chartPresets[this.currentPresetId]);
    this.chartsSubject.next([...this.chartPresets[this.currentPresetId]]);
  }

  private enforceMaxVisibleCharts(): void {
    const currentCharts = this.chartPresets[this.currentPresetId] || [];
    let visibleCount = 0;
    
    const updatedCharts = currentCharts.map(chart => {
      if (chart.visible) {
        if (visibleCount < this.MAX_VISIBLE_CHARTS) {
          visibleCount++;
          return chart;
        } else {
          return { ...chart, visible: false };
        }
      }
      return chart;
    });
    
    this.saveConfiguration(updatedCharts);
  }

  private saveConfiguration(charts: Chart[]): void {
    this.chartPresets[this.currentPresetId] = charts;
    try {
      localStorage.setItem('chartPresets', JSON.stringify(this.chartPresets));
    } catch (error) {
      console.error('Error saving chart configuration:', error);
    }
  }

  // Load saved configuration from localStorage and ensure all default charts exist
  private loadSavedConfiguration(): void {
    try {
      const savedConfig = localStorage.getItem('chartPresets');
      if (savedConfig) {
        this.chartPresets = JSON.parse(savedConfig);

        if (!this.chartPresets[this.currentPresetId]) {
          this.chartPresets[this.currentPresetId] = [...this.defaultCharts];
        } else {
          this.ensureAllDefaultChartsExist(this.currentPresetId);
        }

        this.enforceMaxVisibleCharts();
        this.chartsSubject.next(this.chartPresets[this.currentPresetId]);
      } else {
        // No config found, fallback to default for current preset
        this.chartPresets[this.currentPresetId] = [...this.defaultCharts];
        this.chartsSubject.next(this.defaultCharts);
      }
    } catch (error) {
      console.error('Error loading chart configuration:', error);
      this.chartPresets[this.currentPresetId] = [...this.defaultCharts];
      this.chartsSubject.next(this.defaultCharts);
    }
  }

}