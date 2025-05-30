import { Component, Inject } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { NgClass, NgIf, NgFor } from '@angular/common';

@Component({
  selector: 'app-configpopup',
  imports: [MatDialogModule, MatButtonModule,  NgClass, NgIf, NgFor ],
  templateUrl: './configpopup.component.html',
  styleUrl: './configpopup.component.scss'
})
export class ConfigpopupComponent {
  constructor(@Inject(MAT_DIALOG_DATA) public data: any) {}
  getIncidentKeys(obj: Record<string, number>): string[] {
  return Object.keys(obj);
  }
}
