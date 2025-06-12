import { Component, Inject } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { NgClass } from '@angular/common';

@Component({
  selector: 'app-upload-result-dialog',
  standalone: true,
  imports: [MatDialogModule, MatButtonModule, NgClass],
  templateUrl: './upload-result-dialog.component.html',
  styleUrl: './upload-result-dialog.component.scss'
  
    
  
})
export class UploadResultDialogComponent {
  constructor(@Inject(MAT_DIALOG_DATA) public data: any) {}
  getIncidentKeys(obj: Record<string, number>): string[] {
  return Object.keys(obj);
  }
}