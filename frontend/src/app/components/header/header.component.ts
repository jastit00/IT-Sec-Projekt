import { Component, Inject } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogRef, MatDialogModule } from '@angular/material/dialog';
import { FormsModule } from '@angular/forms';
import { NgIf } from '@angular/common';

@Component({
  selector: 'app-chart-rename-dialog',
  standalone: true,
  imports: [MatDialogModule, FormsModule, NgIf],
  template: `
    <h2 mat-dialog-title>Chart umbenennen</h2>
    <div mat-dialog-content>
      <p>Geben Sie einen neuen Namen für das Diagramm ein:</p>
      <input type="text" [(ngModel)]="chartName" placeholder="Diagramm Name" class="full-width">
      <div *ngIf="nameError" class="error-message">
        {{ nameError }}
      </div>
    </div>
    <div mat-dialog-actions>
      <button mat-button (click)="onCancel()">Abbrechen</button>
      <button mat-button [disabled]="!isNameValid()" (click)="onSave()">Speichern</button>
    </div>
  `,
  styles: [`
    .full-width {
      width: 100%;
      padding: 8px;
      margin: 10px 0;
      box-sizing: border-box;
    }
    .error-message {
      color: red;
      font-size: 12px;
      margin-top: 5px;
    }
  `]
})
export class ChartRenameDialogComponent {
  chartName: string;
  nameError: string = '';

  constructor(
    public dialogRef: MatDialogRef<ChartRenameDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { chartName: string }
  ) {
    this.chartName = data.chartName;
  }

  isNameValid(): boolean {
    if (!this.chartName || this.chartName.trim() === '') {
      this.nameError = 'Der Name darf nicht leer sein.';
      return false;
    }
    this.nameError = '';
    return true;
  }

  onCancel(): void {
    this.dialogRef.close();
  }

  onSave(): void {
    if (this.isNameValid()) {
      this.dialogRef.close(this.chartName);
    }
  }
}