import { Injectable, signal } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

export interface Chart {
  id: string;
  name: string;
  visible: boolean;
}

@Injectable({
  providedIn: 'root'
})
export class ChartVisibilityService {
  // Default chart configuration
  private defaultCharts: Chart[] = [
    { id: 'chart1', name: 'Diagramm 1', visible: true },
    { id: 'chart2', name: 'Diagramm 2', visible: true },
    { id: 'chart3', name: 'Diagramm 3', visible: true },
    { id: 'chart4', name: 'Diagramm 4', visible: true },
    { id: 'chart6', name: 'Diagramm 6', visible: true }
  ];

  // BehaviorSubject to track chart visibility state
  private chartsSubject = new BehaviorSubject<Chart[]>(this.defaultCharts);
  
  // Observable that components can subscribe to
  public charts$: Observable<Chart[]> = this.chartsSubject.asObservable();

  constructor() {
    // Try to load saved configuration from localStorage
    this.loadSavedConfiguration();
  }

  /**
   * Toggle the visibility of a chart by its ID
   * @param id The ID of the chart to toggle
   */
  toggleChartVisibility(id: string): void {
    const currentCharts = this.chartsSubject.getValue();
    const updatedCharts = currentCharts.map(chart => {
      if (chart.id === id) {
        return { ...chart, visible: !chart.visible };
      }
      return chart;
    });
    
    this.chartsSubject.next(updatedCharts);
    this.saveConfiguration(updatedCharts);
  }

  /**
   * Set the visibility of a chart by its ID
   * @param id The ID of the chart
   * @param visible The visibility state to set
   */
  setChartVisibility(id: string, visible: boolean): void {
    const currentCharts = this.chartsSubject.getValue();
    const updatedCharts = currentCharts.map(chart => {
      if (chart.id === id) {
        return { ...chart, visible };
      }
      return chart;
    });
    
    this.chartsSubject.next(updatedCharts);
    this.saveConfiguration(updatedCharts);
  }

  /**
   * Get the current visibility state of all charts
   */
  getVisibleCharts(): string[] {
    return this.chartsSubject.getValue()
      .filter(chart => chart.visible)
      .map(chart => chart.id);
  }

  /**
   * Get all charts (visible and hidden)
   */
  getAllCharts(): Chart[] {
    return this.chartsSubject.getValue();
  }

  /**
   * Add a new chart or update an existing one
   * @param chart The chart to add or update
   */
  addChart(chart: Chart): void {
    const currentCharts = this.chartsSubject.getValue();
    const existingChartIndex = currentCharts.findIndex(c => c.id === chart.id);
    
    if (existingChartIndex >= 0) {
      // Update existing chart
      const updatedCharts = [...currentCharts];
      updatedCharts[existingChartIndex] = chart;
      this.chartsSubject.next(updatedCharts);
    } else {
      // Add new chart
      const updatedCharts = [...currentCharts, chart];
      this.chartsSubject.next(updatedCharts);
    }
    
    this.saveConfiguration(this.chartsSubject.getValue());
  }

  /**
   * Reset all charts to their default visibility
   */
  resetToDefaults(): void {
    this.chartsSubject.next(this.defaultCharts);
    this.saveConfiguration(this.defaultCharts);
  }

  /**
   * Save the current configuration to localStorage
   */
  private saveConfiguration(charts: Chart[]): void {
    try {
      localStorage.setItem('chartConfiguration', JSON.stringify(charts));
    } catch (error) {
      console.error('Error saving chart configuration:', error);
    }
  }

  /**
   * Load saved configuration from localStorage and ensure all default charts exist
   */
  private loadSavedConfiguration(): void {
    try {
      const savedConfig = localStorage.getItem('chartConfiguration');
      if (savedConfig) {
        let parsedConfig = JSON.parse(savedConfig) as Chart[];
        
        // Ensure all default charts exist in the loaded configuration
        this.defaultCharts.forEach(defaultChart => {
          if (!parsedConfig.some(chart => chart.id === defaultChart.id)) {
            parsedConfig.push(defaultChart);
          }
        });
        
        this.chartsSubject.next(parsedConfig);
      }
    } catch (error) {
      console.error('Error loading chart configuration:', error);
      // Fallback to defaults on error
      this.chartsSubject.next(this.defaultCharts);
    }
  }
}