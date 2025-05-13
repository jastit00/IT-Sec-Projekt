import { Component, Inject } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { NgClass, NgIf } from '@angular/common';

@Component({
  selector: 'app-upload-result-dialog',
  standalone: true,
  imports: [MatDialogModule, MatButtonModule,  NgClass, NgIf],
  template: `
    <h2 mat-dialog-title [ngClass]="{ 'error-title': data.status === 'error' }">
      {{ data.status === 'error' ? 'Fehler beim Upload' : 'Upload erfolgreich' }}
    </h2>

    <div mat-dialog-content>
      <ng-container *ngIf="data.status === 'error'; else successContent">
        <p><strong>Fehlermeldung:</strong> {{ data.message }}</p>
      </ng-container>

      <ng-template #successContent>
        <table>
          <tr>
            <td><strong>ID:</strong></td>
            <td>{{ data.id }}</td>
          </tr>
          <tr>
            <td><strong>Status:</strong></td>
            <td>{{ data.status }}</td>
          </tr>
          <tr NgIf="data.filename !== null; else noFilename">
            <td><strong>Name:</strong></td>
            <td>{{ data.filename }}</td>
          </tr>
          <ng-template #noFilename>
            <tr>
              <td><strong>Name:</strong></td>
              <td><em>Kein Dateiname verfügbar</em></td>
            </tr>
          </ng-template>
        </table>
      </ng-template>
    </div>

    <div mat-dialog-actions align="end">
      <button mat-button mat-dialog-close>OK</button>
    </div>
  `,
  styles: [`
    .error-title {
      color: #b00020;
    }
    table {
      width: 100%;
      border-spacing: 8px;
    }
    td:first-child {
      font-weight: bold;
      width: 100px;
    }
  `]
})
export class UploadResultDialogComponent {
  constructor(@Inject(MAT_DIALOG_DATA) public data: any) {}
}