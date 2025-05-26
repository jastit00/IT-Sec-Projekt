import { Component } from '@angular/core';
import { EventService, SecurityEvent } from '../../services/event-service';
import { CommonModule } from '@angular/common';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatIconModule } from '@angular/material/icon';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-critical-events',
  standalone: true,
  imports: [
    CommonModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatIconModule,
    FormsModule
  ],
  templateUrl: './critical-events.component.html',
  styleUrls: ['./critical-events.component.scss']
})
export class CriticalEventsComponent {
  events: SecurityEvent[];
  filteredEvents: SecurityEvent[];
  searchTerm: string = '';
  sortDirection: string = '';

  constructor(private eventService: EventService) {
    this.events = this.eventService.getCriticalEvents();
    this.filteredEvents = [...this.events];
  }

  filterEvents() {
    this.sortEvents();
  }

  sortEvents() {
    // Erst nach Suchbegriff filtern (nur Critical Events)
    const criticalEvents = this.eventService.getCriticalEvents();
    
    if (!this.searchTerm.trim()) {
      this.filteredEvents = [...criticalEvents];
    } else {
      this.filteredEvents = criticalEvents.filter(event => 
        this.matchesSearchTerm(event)
      );
    }

    // Dann nach sortDirection sortieren (alle Critical Events werden sortiert)
    if (this.sortDirection && this.filteredEvents.length > 0) {
      this.filteredEvents.sort((a, b) => {
        let comparison = 0;
        
        // Sortierung nach Datum (primär)
        const dateA = new Date(a.date);
        const dateB = new Date(b.date);
        comparison = dateA.getTime() - dateB.getTime();
        
        // Falls Datum gleich ist, nach Event-Typ sortieren
        if (comparison === 0) {
          comparison = a.event.toLowerCase().localeCompare(b.event.toLowerCase());
        }
        
        // Falls Event-Typ auch gleich ist, nach Description sortieren
        if (comparison === 0) {
          comparison = a.description.toLowerCase().localeCompare(b.description.toLowerCase());
        }
        
        // Sortierrichtung anwenden
        return this.sortDirection === 'desc' ? -comparison : comparison;
      });
    }
  }

  private matchesSearchTerm(event: SecurityEvent): boolean {
    if (!this.searchTerm.trim()) return true;
    
    const search = this.searchTerm.toLowerCase();
    return event.date.toLowerCase().includes(search) ||
           event.event.toLowerCase().includes(search) ||
           event.status.toLowerCase().includes(search) ||
           event.description.toLowerCase().includes(search) ||
           event.ips?.some(ip => ip.toLowerCase().includes(search));
  }
}