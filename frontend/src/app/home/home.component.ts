import { Component, HostListener, inject, OnInit, OnDestroy } from '@angular/core';
import { CdkDragDrop, moveItemInArray } from '@angular/cdk/drag-drop';
import { ChartOneComponent } from '../components/chart-one/chart-one.component';
import { ChartTwoComponent } from '../components/chart-two/chart-two.component';
import { ChartThreeComponent } from '../components/chart-three/chart-three.component';
import { ChartFourComponent } from '../components/chart-four/chart-four.component';
import { ChartSixComponent } from '../components/chart-six/chart-six.component'; // Neue Komponente importieren
import { CommonModule } from '@angular/common';
import { DragDropModule } from '@angular/cdk/drag-drop';
import { ChartVisibilityService } from '../services/chart-visibility.service';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-home',
  standalone: true,
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.scss'],
  imports: [
    CommonModule,
    DragDropModule,
    ChartOneComponent,
    ChartTwoComponent,
    ChartThreeComponent,
    ChartFourComponent,
    ChartSixComponent // ChartSixComponent zu den Imports hinzufügen
  ]
})
export class HomeComponent implements OnInit, OnDestroy {
  chartIds: string[] = [];
  
  // Resize Variablen
  resizing = false;
  resizeDirection: 'horizontal' | 'vertical' | 'both' | null = null;
  resizeChartElement: HTMLElement | null = null;
  startX = 0;
  startY = 0;
  startWidth = 0;
  startHeight = 0;
  
  private chartVisibilityService = inject(ChartVisibilityService);
  private subscription: Subscription | null = null;

  ngOnInit() {
    // Initial state
    this.updateVisibleCharts();
    
    // Subscribe to chart visibility changes
    this.subscription = this.chartVisibilityService.charts$.subscribe(() => {
      this.updateVisibleCharts();
    });
  }
  
  ngOnDestroy() {
    // Clean up subscription when component is destroyed
    if (this.subscription) {
      this.subscription.unsubscribe();
    }
  }
  
  // Update the charts that should be displayed
  updateVisibleCharts() {
    this.chartIds = this.chartVisibilityService.getVisibleCharts();
  }
  
  // Chart Drag & Drop
  drop(event: CdkDragDrop<string[]>) {
    moveItemInArray(this.chartIds, event.previousIndex, event.currentIndex);
  }
  
  // Chart Typ überprüfen
  isChart(id: string, type: string): boolean {
    return id === type;
  }
  
  // Resize handle Mousedown
  onResizeStart(event: MouseEvent, direction: 'horizontal' | 'vertical' | 'both') {
    // Verhindern, dass das Drag-Event ausgelöst wird
    event.preventDefault();
    event.stopPropagation();
    // Get das Chart-Element
    const chartElement = (event.target as HTMLElement).closest('.chart-box') as HTMLElement;
    if (!chartElement) return;
    // Resizing starten
    this.resizing = true;
    this.resizeDirection = direction;
    this.resizeChartElement = chartElement;
    // Startposition und -größe speichern
    this.startX = event.clientX;
    this.startY = event.clientY;
    this.startWidth = chartElement.offsetWidth;
    this.startHeight = chartElement.offsetHeight;
    // CSS-Klasse für visuelles Feedback hinzufügen
    chartElement.classList.add('resizing');
  }
  
  // Mouse move während Resize
  @HostListener('document:mousemove', ['$event'])
  onMouseMove(event: MouseEvent) {
    if (!this.resizing || !this.resizeChartElement) return;
    const deltaX = event.clientX - this.startX;
    const deltaY = event.clientY - this.startY;
    // Horizontales Resizing
    if (this.resizeDirection === 'horizontal' || this.resizeDirection === 'both') {
      const newWidth = Math.max(150, this.startWidth + deltaX);
      this.resizeChartElement.style.width =`${newWidth}px`;
    }
    // Vertikales Resizing
    if (this.resizeDirection === 'vertical' || this.resizeDirection === 'both') {
      const newHeight = Math.max(150, this.startHeight + deltaY);
      this.resizeChartElement.style.height =`${newHeight}px`;
    }
  }
  
  // Mouse up zum Beenden des Resizings
  @HostListener('document:mouseup')
  onMouseUp() {
    if (this.resizing && this.resizeChartElement) {
      // Resizing-Klasse entfernen
      this.resizeChartElement.classList.remove('resizing');
      // Resize-Status zurücksetzen
      this.resizing = false;
      this.resizeDirection = null;
      this.resizeChartElement = null;
    }
  }
}