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
  // Maximale Anzahl gleichzeitig sichtbarer Diagramme
  private readonly MAX_VISIBLE_CHARTS = 4;

  // Default chart configuration
  private defaultCharts: Chart[] = [
    { id: 'chart1', name: 'test', visible: true },
    { id: 'chart2', name: 'Diagramm 2', visible: true },
    { id: 'chart3', name: 'Diagramm 3', visible: true },
    { id: 'chart4', name: 'Diagramm 4', visible: true },
    { id: 'chart5', name: 'Diagramm 5', visible: false },
    { id: 'chart6', name: 'Diagramm 6', visible: false },
    { id: 'config-changes', name: 'Diagramm 7', visible: false },
    { id: 'chart8', name: 'Diagramm 8', visible: false }, // Default auf false gesetzt, da Max = 4
  ];

  private chartPresets: { [presetId: string]: Chart[] } = {};
  // BehaviorSubject to track chart visibility state
  private chartsSubject = new BehaviorSubject<Chart[]>(this.defaultCharts);
  
  // Observable that components can subscribe to
  public charts$: Observable<Chart[]> = this.chartsSubject.asObservable();

  constructor(private presetIdService: PresetIdService) {
    // Try to load saved configuration from localStorage
    this.loadSavedConfiguration();
    this.presetIdService.presetId$.subscribe(() => {
      this.updateChartsForCurrentPreset();
    });
    
    //this.enforceMaxVisibleCharts();
  }

  private get currentPresetId(): string {
    return this.presetIdService.getPresetId() || '1';   // Default to 1 if no preset ID is set
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


  /**
   * Toggle the visibility of a chart by its ID
   * @param id The ID of the chart to toggle
   * @returns boolean indicating if the operation was successful
   */
  toggleChartVisibility(id: string): boolean {
    const currentCharts = this.chartPresets[this.currentPresetId] || [...this.defaultCharts];
    const chart = currentCharts.find(c => c.id === id);
    if (!chart) return false;
    
    // Wenn das Diagramm bereits sichtbar ist, einfach ausblenden
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

  /**
   * Set the visibility of a chart by its ID
   * @param id The ID of the chart
   * @param visible The visibility state to set
   * @returns boolean indicating if the operation was successful
   */
  setChartVisibility(chartId: string, visible: boolean): boolean {
    const charts = this.chartPresets[this.currentPresetId] || [...this.defaultCharts];
    const chart = charts.find(c => c.id === chartId);
    if (!chart) return false;
    // Wenn das Diagramm eingeblendet werden soll
    if (visible && !chart.visible && this.getVisibleChartsCount() >= this.MAX_VISIBLE_CHARTS) {
      console.warn(`Maximale Anzahl an Diagrammen (${this.MAX_VISIBLE_CHARTS}) erreicht.`);
      return false;
    }

    chart.visible = visible;
    this.saveConfiguration(charts);
    this.chartsSubject.next([...charts]);
    return true;
  }

  /**
   * Get the current visibility state of all charts
   */
  getVisibleCharts(): string[] {
    const charts = this.chartPresets[this.currentPresetId] || [];
    return charts.filter(c => c.visible).map(c => c.id);
  }

  /**
   * Get the count of currently visible charts
   */
  getVisibleChartsCount(): number {
    return this.getVisibleCharts().length;
  }

  /**
   * Check if the maximum number of visible charts is reached
   */
  isMaxChartsReached(): boolean {
    return this.getVisibleChartsCount() >= this.MAX_VISIBLE_CHARTS;
  }

  /**
   * Get all charts (visible and hidden)
   */
  getAllCharts(): Chart[] {
    return this.chartPresets[this.currentPresetId] || this.chartPresets['1'];
  }

  /**
   * Add a new chart or update an existing one
   * @param chart The chart to add or update
   */
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

    // Wenn das neue Diagramm sichtbar sein soll
    /*if (chart.visible) {
      const existingChart = existingChartIndex >= 0 ? currentCharts[existingChartIndex] : null;
      
      // Wenn es ein neues Chart ist oder ein bestehendes von unsichtbar auf sichtbar geändert wird
      if (!existingChart || !existingChart.visible) {
        // Prüfen, ob das Maximum erreicht ist
        if (this.getVisibleChartsCount() >= this.MAX_VISIBLE_CHARTS) {
          console.warn(`Maximale Anzahl an Diagrammen (${this.MAX_VISIBLE_CHARTS}) bereits erreicht!`);
          
          // Chart hinzufügen, aber als unsichtbar
          const updatedChart = { ...chart, visible: false };
          
          if (existingChartIndex >= 0) {
            // Update existing chart
            const updatedCharts = [...currentCharts];
            updatedCharts[existingChartIndex] = updatedChart;
            this.chartsSubject.next(updatedCharts);
          } else {
            // Add new chart
            const updatedCharts = [...currentCharts, updatedChart];
            this.chartsSubject.next(updatedCharts);
          }
          
          this.saveConfiguration(this.chartsSubject.getValue());
          return false;
        }
      }
    }*/
  }

  /**
   * Reset all charts to their default visibility
   */
  resetToDefaults(): void {
    this.chartPresets[this.currentPresetId] = [...this.defaultCharts];
    this.enforceMaxVisibleCharts();
    this.saveConfiguration(this.chartPresets[this.currentPresetId]);
    this.chartsSubject.next([...this.chartPresets[this.currentPresetId]]);
  }

  /**
   * Enforce the maximum number of visible charts
   * Ensures that no more than MAX_VISIBLE_CHARTS are visible
   */
  private enforceMaxVisibleCharts(): void {
    const currentCharts = this.chartPresets[this.currentPresetId] || [];
    let visibleCount = 0;
    
    const updatedCharts = currentCharts.map(chart => {
      // Wenn das Chart sichtbar ist
      if (chart.visible) {
        // Wenn wir das Maximum noch nicht erreicht haben
        if (visibleCount < this.MAX_VISIBLE_CHARTS) {
          visibleCount++;
          return chart;
        } else {
          // Maximum erreicht, weitere Charts ausblenden
          return { ...chart, visible: false };
        }
      }
      return chart;
    });
    
    this.saveConfiguration(updatedCharts);

    /*if (visibleCount >= this.MAX_VISIBLE_CHARTS) {
      this.chartsSubject.next(updatedCharts);
      this.saveConfiguration(updatedCharts);
    }*/
  }

  /**
   * Save the current configuration to localStorage
   */
  private saveConfiguration(charts: Chart[]): void {
    this.chartPresets[this.currentPresetId] = charts;
    try {
      localStorage.setItem('chartPresets', JSON.stringify(this.chartPresets));
    } catch (error) {
      console.error('Error saving chart configuration:', error);
    }
  }

  /**
   * Load saved configuration from localStorage and ensure all default charts exist
   */
  private loadSavedConfiguration(): void {
    try {
      const savedConfig = localStorage.getItem('chartPresets');
      if (savedConfig) {
        this.chartPresets = JSON.parse(savedConfig);

        // Ensure current preset exists
        if (!this.chartPresets[this.currentPresetId]) {
          this.chartPresets[this.currentPresetId] = [...this.defaultCharts];
        } else {
          // Patch missing default charts into the current preset
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
      // Fallback to defaults on error
      this.chartPresets[this.currentPresetId] = [...this.defaultCharts];
      this.chartsSubject.next(this.defaultCharts);
    }
  }

}