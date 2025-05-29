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
  // Maximale Anzahl gleichzeitig sichtbarer Diagramme
  private readonly MAX_VISIBLE_CHARTS = 4;

  // Default chart configuration
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

  // BehaviorSubject to track chart visibility state
  private chartsSubject = new BehaviorSubject<Chart[]>(this.defaultCharts);
  
  // Observable that components can subscribe to
  public charts$: Observable<Chart[]> = this.chartsSubject.asObservable();

  constructor() {
    // Try to load saved configuration from localStorage
    this.loadSavedConfiguration();
    
    // Stellen Sie sicher, dass beim Start nicht mehr als MAX_VISIBLE_CHARTS sichtbar sind
    this.enforceMaxVisibleCharts();
  }

  /**
   * Toggle the visibility of a chart by its ID
   * @param id The ID of the chart to toggle
   * @returns boolean indicating if the operation was successful
   */
  toggleChartVisibility(id: string): boolean {
    const currentCharts = this.chartsSubject.getValue();
    const chart = currentCharts.find(c => c.id === id);
    
    if (!chart) return false;
    
    // Wenn das Diagramm bereits sichtbar ist, einfach ausblenden
    if (chart.visible) {
      const updatedCharts = currentCharts.map(c => {
        if (c.id === id) {
          return { ...c, visible: false };
        }
        return c;
      });
      
      this.chartsSubject.next(updatedCharts);
      this.saveConfiguration(updatedCharts);
      return true;
    } 
    // Wenn Diagramm eingeblendet werden soll, prüfen ob das Maximum erreicht ist
    else {
      const visibleCount = this.getVisibleChartsCount();
      
      if (visibleCount < this.MAX_VISIBLE_CHARTS) {
        const updatedCharts = currentCharts.map(c => {
          if (c.id === id) {
            return { ...c, visible: true };
          }
          return c;
        });
        
        this.chartsSubject.next(updatedCharts);
        this.saveConfiguration(updatedCharts);
        return true;
      } else {
        console.warn(`Maximale Anzahl an Diagrammen (${this.MAX_VISIBLE_CHARTS}) bereits erreicht!`);
        return false;
      }
    }
  }

  /**
   * Set the visibility of a chart by its ID
   * @param id The ID of the chart
   * @param visible The visibility state to set
   * @returns boolean indicating if the operation was successful
   */
  setChartVisibility(id: string, visible: boolean): boolean {
    // Wenn das Diagramm eingeblendet werden soll
    if (visible) {
      // Prüfen, ob das Maximum erreicht ist
      const visibleCount = this.getVisibleChartsCount();
      const currentCharts = this.chartsSubject.getValue();
      const chart = currentCharts.find(c => c.id === id);
      
      // Nur prüfen, wenn das Chart noch nicht sichtbar ist
      if (chart && !chart.visible && visibleCount >= this.MAX_VISIBLE_CHARTS) {
        console.warn(`Maximale Anzahl an Diagrammen (${this.MAX_VISIBLE_CHARTS}) bereits erreicht!`);
        return false;
      }
    }
    
    const currentCharts = this.chartsSubject.getValue();
    const updatedCharts = currentCharts.map(chart => {
      if (chart.id === id) {
        return { ...chart, visible };
      }
      return chart;
    });
    
    this.chartsSubject.next(updatedCharts);
    this.saveConfiguration(updatedCharts);
    return true;
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
    return this.chartsSubject.getValue();
  }

  /**
   * Add a new chart or update an existing one
   * @param chart The chart to add or update
   */
  addChart(chart: Chart): boolean {
    const currentCharts = this.chartsSubject.getValue();
    const existingChartIndex = currentCharts.findIndex(c => c.id === chart.id);
    
    // Wenn das neue Diagramm sichtbar sein soll
    if (chart.visible) {
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
    }
    
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
    return true;
  }

  /**
   * Reset all charts to their default visibility
   */
  resetToDefaults(): void {
    this.chartsSubject.next(this.defaultCharts);
    this.saveConfiguration(this.defaultCharts);
    // Nach Reset sicherstellen, dass nicht mehr als erlaubt sichtbar sind
    this.enforceMaxVisibleCharts();
  }

  /**
   * Enforce the maximum number of visible charts
   * Ensures that no more than MAX_VISIBLE_CHARTS are visible
   */
  private enforceMaxVisibleCharts(): void {
    const currentCharts = this.chartsSubject.getValue();
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
    
    if (visibleCount >= this.MAX_VISIBLE_CHARTS) {
      this.chartsSubject.next(updatedCharts);
      this.saveConfiguration(updatedCharts);
    }
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