import { Component } from '@angular/core';
import { EventService, SecurityEvent } from '../../services/event-service';

import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatIconModule } from '@angular/material/icon';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-critical-events',
  standalone: true,
  imports: [
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
    // Filter by search 
    const criticalEvents = this.eventService.getCriticalEvents();
    
    if (!this.searchTerm.trim()) {
      this.filteredEvents = [...criticalEvents];
    } else {
      this.filteredEvents = criticalEvents.filter(event => 
        this.matchesSearchTerm(event)
      );
    }

    // sort by sortDirection
    if (this.sortDirection && this.filteredEvents.length > 0) {
      this.filteredEvents.sort((a, b) => {
        let comparison = 0;
        
        // sort by date
        const dateA = new Date(a.date);
        const dateB = new Date(b.date);
        comparison = dateA.getTime() - dateB.getTime();
        
        // sort by event type
        if (comparison === 0) {
          comparison = a.event.toLowerCase().localeCompare(b.event.toLowerCase());
        }
        
        // sort by description
        if (comparison === 0) {
          comparison = a.description.toLowerCase().localeCompare(b.description.toLowerCase());
        }
        
        // apply sorting direction
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