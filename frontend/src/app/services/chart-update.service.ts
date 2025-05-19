import { Injectable } from '@angular/core';
import { Subject } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class ChartUpdateService {
  private updateChartSubject = new Subject<void>();
  updateChart$ = this.updateChartSubject.asObservable();

  triggerChartUpdate(): void {
    this.updateChartSubject.next();
  }
}