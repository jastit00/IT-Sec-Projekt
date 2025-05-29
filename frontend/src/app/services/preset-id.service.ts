import { Injectable } from '@angular/core';
import { NavigationEnd, Router } from '@angular/router';
import { BehaviorSubject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class PresetIdService {
  private presetId: string = '1'; // default to '1'
  private presetIdSubject = new BehaviorSubject<string>(this.presetId);
  public presetId$ = this.presetIdSubject.asObservable();

  public setPresetId(id: string): void {
    this.presetId = id;
    this.presetIdSubject.next(id);
  }

  public getPresetId(): string {
    return this.presetId;
  }
}
