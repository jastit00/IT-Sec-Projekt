import { Component } from '@angular/core';

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
  private _searchTerm: string = '';
  sortBy: string = '';
  sortDirection: string = '';

  private readonly FORBIDDEN_CHARS = /[<>"';[\]{}()\\\/]/g;

  constructor(private eventService: EventService) {
    this.events = this.eventService.getAllEvents();
    this.filteredEvents = [...this.events];
  }

  get searchTerm(): string {
    return this._searchTerm;
  }

  set searchTerm(value: string) {
    this._searchTerm = value ? value.replace(this.FORBIDDEN_CHARS, '').trim() : '';
  }

  filterEvents() {
    this.sortEvents();
  }

  sortEvents() {
    const normalize = (str: string) => str.toLowerCase().replace(/\s+/g, '');
    
    // filter by sortBy
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
    // sort by SortDirection
    if (this.sortDirection && this.filteredEvents.length > 0) {
      this.filteredEvents.sort((a, b) => {
        let comparison = 0;
        
        // sort by Date
        const dateA = new Date(a.date);
        const dateB = new Date(b.date);
        comparison = dateA.getTime() - dateB.getTime();
        
        // sort by Event type
        if (comparison === 0) {
          comparison = a.event.toLowerCase().localeCompare(b.event.toLowerCase());
        }
        
        // sort by Event state
        if (comparison === 0) {
          const statusOrder = { 'Critical': 3, 'Warning': 2, 'Normal': 1 };
          const statusA = statusOrder[a.status] || 0;
          const statusB = statusOrder[b.status] || 0;
          comparison = statusA - statusB;
        }
        
        // Apply Direction
        return this.sortDirection === 'desc' ? -comparison : comparison;
      });
    }
  }

  private matchesSearchTerm(event: SecurityEvent): boolean {
    if (!this._searchTerm.trim()) return true;
    
    const search = this._searchTerm.toLowerCase();
    return event.date.toLowerCase().includes(search) ||
           event.event.toLowerCase().includes(search) ||
           event.status.toLowerCase().includes(search) ||
           event.description.toLowerCase().includes(search) ||
           event.ips?.some(ip => ip.toLowerCase().includes(search));
  }

  onKeyPress(event: KeyboardEvent) {
    const forbiddenChars = '<>"\;[]{}()/';
    if (forbiddenChars.includes(event.key)) {
      event.preventDefault();
      console.log("test forbidden characters:", event.key);
    }
  }
}