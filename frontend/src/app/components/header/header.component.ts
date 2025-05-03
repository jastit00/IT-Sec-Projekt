import { Component, input, signal, inject } from '@angular/core';
import { logout } from '../../auth/keycloak.service';
import { RouterLink } from '@angular/router';
import { DefaultService } from '../../api-client';

@Component({
  selector: 'app-header',
  imports: [RouterLink],
  templateUrl: './header.component.html',
  styleUrl: './header.component.scss'
})

export class HeaderComponent {
  title = signal('Security Event Detection');
  user = input('User');

  private defaultService = inject(DefaultService);

  logout() {
    logout();
  }

   //Methode wird aufgerufen wenn Datei ausgewählrt wird
  onFileSelected($event: Event) {
     // Die Dateien aus dem Event extrahieren
    const input = $event.target as HTMLInputElement;
    // Holt die ausgewählten Dateien
    const files = input.files;
    
    // Wenn Dateien ausgewählt wurden, gebe sie in der Konsole aus
    if (files && files.length > 0) {
      //console.log('Dateien ausgewählt:', Array.from(files)); // Array von Dateien in der Konsole ausgeben
      this.defaultService.logfilesPost(files[0]).subscribe({
        next: (result) => {
          console.log('Upload erfolgreich:', result);
        },
        error: (err) => {
          console.error('Fehler beim Upload:', err);
        }
      });
    }
  }
  // Methode, die den Dateiauswahldialog öffnet
  openFileUpload() {
    // Sucht das Datei-Input-Element im DOM
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    
    // Wenn das Input-Element gefunden wurde, simuliert einen Klick darauf, um den Dateiauswahldialog zu öffnen
    if (fileInput) {
      fileInput.click();
    }
  }  
  
}
