import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatIconModule } from '@angular/material/icon';
import { FormsModule } from '@angular/forms';
import { EventService, SecurityEvent } from '../../services/event-service';

@Component({
  selector: 'app-all-events',
  standalone: true,
  imports: [
    CommonModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatIconModule,
    FormsModule
  ],
  templateUrl: './all-events.component.html',
  styleUrls: ['./all-events.component.scss']
})
export class AllEventsComponent {
  events: SecurityEvent[] = [];
  filteredEvents: SecurityEvent[] = [];
  searchTerm: string = '';
  sortBy: string = '';
  sortDirection: string = '';

  constructor(private eventService: EventService) {
    this.events = this.eventService.getAllEvents();
    this.filteredEvents = [...this.events];
  }

  filterEvents() {
    this.sortEvents();
  }

  sortEvents() {
    const normalize = (str: string) => str.toLowerCase().replace(/\s+/g, '');
    
    // Erst nach sortBy filtern oder alle Events nehmen
    if (!this.sortBy) {
      this.filteredEvents = this.events.filter(event =>
        this.matchesSearchTerm(event)
      );
    } else {
      this.filteredEvents = this.events.filter(event => {
        const matchesSort = normalize(event.status) === normalize(this.sortBy) ||
                            normalize(event.event) === normalize(this.sortBy);
        const matchesSearch = this.matchesSearchTerm(event);
        return matchesSort && matchesSearch;
      });
    }

    // Dann nach sortDirection sortieren
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
        
        // Falls Event-Typ auch gleich ist, nach Status sortieren
        if (comparison === 0) {
          const statusOrder = { 'Critical': 3, 'Warning': 2, 'Normal': 1 };
          const statusA = statusOrder[a.status] || 0;
          const statusB = statusOrder[b.status] || 0;
          comparison = statusA - statusB;
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