// home.component.ts
import { Component, AfterViewInit, QueryList, ViewChildren, ElementRef, Renderer2 } from '@angular/core';
import { ChartOneComponent } from '../components/chart-one/chart-one.component';
import { ChartTwoComponent } from '../components/chart-two/chart-two.component';
import { ChartThreeComponent } from '../components/chart-three/chart-three.component';
import { ChartFourComponent } from '../components/chart-four/chart-four.component';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.scss'],
  imports: [ChartOneComponent, ChartTwoComponent, ChartThreeComponent, ChartFourComponent]
})
export class HomeComponent implements AfterViewInit {
  @ViewChildren('gridBox') gridBoxes!: QueryList<ElementRef>;
  
  private draggedBox: HTMLElement | null = null;
  private resizingBox: HTMLElement | null = null;
  private originalSize = { width: 0, height: 0 };
  private originalPosition = { x: 0, y: 0 };
  
  constructor(private renderer: Renderer2) {}

  ngAfterViewInit() {
    //Warten, bis View geladen ist
    setTimeout(() => {
      this.setupDragAndDrop(); //Setup für Drag and Drop
      this.setupResizeHandlers(); //Setup für Resizing
    }, 0);
  }

  private setupDragAndDrop() {
    //Für jede Box im Grid
    this.gridBoxes.forEach(boxRef => {
      const box = boxRef.nativeElement;
      
      //Dragstart, wenn Drag beginnt
      this.renderer.listen(box, 'dragstart', (event: DragEvent) => {
        if (this.resizingBox) {
          event.preventDefault(); //Drag nicht starten, wenn Resizing läuft
          return;
        }
        
        this.draggedBox = box;
        this.renderer.addClass(box, 'dragging');
        
        if (event.dataTransfer) {
          event.dataTransfer.setData('text/plain', box.id); //Box-ID für Transfer speichern
          event.dataTransfer.effectAllowed = 'move';
        }
      });
      
      //Dragend, wenn der Drag endet
      this.renderer.listen(box, 'dragend', () => {
        if (this.draggedBox) {
          this.renderer.removeClass(this.draggedBox, 'dragging');
          this.draggedBox = null;
        }
      });
      
      //Dragover, wenn Element über Zielbox gezogen wird
      this.renderer.listen(box, 'dragover', (event: DragEvent) => {
        event.preventDefault(); //Muss verhindert werden, damit das Drop funktioniert
        if (this.draggedBox && this.draggedBox !== box) {
          this.renderer.addClass(box, 'dragover');
        }
      });
      
      //dragleave, wenn das Element die Zielbox verlässt
      this.renderer.listen(box, 'dragleave', () => {
        this.renderer.removeClass(box, 'dragover');
      });
      
      //drop, wenn das Element in eine Box abgelegt wird
      this.renderer.listen(box, 'drop', (event: DragEvent) => {
        event.preventDefault();
        this.renderer.removeClass(box, 'dragover');
        
        if (!this.draggedBox || this.draggedBox === box) {
          return;
        }
        
        //hol die Chart-Elemente
        const draggedChart = this.draggedBox.querySelector('app-chart-one, app-chart-two, app-chart-three, app-chart-four');
        const targetChart = box.querySelector('app-chart-one, app-chart-two, app-chart-three, app-chart-four');
        
        if (draggedChart && targetChart) {
          //klone Chart-Elemente, um sie zu tauschen
          const draggedChartClone = draggedChart.cloneNode(true);
          const targetChartClone = targetChart.cloneNode(true);
          
          //tausche die Chart-Elemente
          draggedChart.parentNode?.replaceChild(targetChartClone, draggedChart);
          targetChart.parentNode?.replaceChild(draggedChartClone, targetChart);
        }
        
        this.draggedBox = null;
      });
    });
  }

  private setupResizeHandlers() {
    //für jede Box im Grid Resizing einrichten
    this.gridBoxes.forEach(boxRef => {
      const box = boxRef.nativeElement;
      const resizeHandle = box.querySelector('.resize-handle');
      
      if (resizeHandle) {
        this.renderer.listen(resizeHandle, 'mousedown', (event: MouseEvent) => {
          event.preventDefault();
          event.stopPropagation();
          
          this.resizingBox = box;
          this.renderer.addClass(box, 'resizing');
          
          this.originalSize = {
            width: box.offsetWidth,
            height: box.offsetHeight
          };
          
          this.originalPosition = {
            x: event.clientX,
            y: event.clientY
          };
          
          const mouseMoveHandler = (moveEvent: MouseEvent) => {
            if (!this.resizingBox) return;
            
            const deltaWidth = moveEvent.clientX - this.originalPosition.x;
            const deltaHeight = moveEvent.clientY - this.originalPosition.y;
            
            this.renderer.setStyle(
              this.resizingBox, 
              'width', 
              `${this.originalSize.width + deltaWidth}px`
            );
            this.renderer.setStyle(
              this.resizingBox, 
              'height', 
              `${this.originalSize.height + deltaHeight}px`
            );
          };
          
          const mouseUpHandler = () => {
            if (this.resizingBox) {
              this.renderer.removeClass(this.resizingBox, 'resizing');
              this.resizingBox = null;
            }
            
            document.removeEventListener('mousemove', mouseMoveHandler);
            document.removeEventListener('mouseup', mouseUpHandler);
          };
          
          document.addEventListener('mousemove', mouseMoveHandler);
          document.addEventListener('mouseup', mouseUpHandler);
        });
      }
    });
  }
}
