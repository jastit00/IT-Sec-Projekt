import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, map, catchError, of, tap, finalize } from 'rxjs';
// Import the DefaultService from the API client
import { DefaultService } from '../api-client';
// Import the Events interface from our models folder
import { Events } from '../models/events.model';
// Frontend interface for security events
export interface SecurityEvent {
  id: number;
  date: string;
  relativeTime: string;
  event: string;
  status: 'Kritisch' | 'Warnung' | 'Normal';
  ips: string[];
}
@Injectable({
  providedIn: 'root'
})
export class EventService {
  // Use inject instead of constructor injection
  private defaultService = inject(DefaultService);
  private httpClient = inject(HttpClient);
  private apiBaseUrl = 'http://localhost:8000/api'; // Base URL for direct HTTP calls
  
  // Current events from the API call
  events: SecurityEvent[] = [];
  loading = false;
  constructor() {
    // Load data on initialization
    this.loadEventsFromBackend().subscribe(); // Direkt subscribe, sonst lädt es nicht
  }
  // Method to load data from the backend
  loadEventsFromBackend(): Observable<SecurityEvent[]> {
    this.loading = true;
    
    return this.getUnifiedEvents().pipe(
      map((backendEvents: Events[]) => this.mapBackendEventsToSecurityEvents(backendEvents)),
      tap(mappedEvents => {
        this.events = mappedEvents;
      }),
      catchError(error => {
        console.error('Error loading events:', error);
        this.events = [];
        return of([]);
      }),
      finalize(() => {
        this.loading = false;
      })
    );
  }
  
  // API call to the backend using the correct endpoint URL that exists in the backend
  getUnifiedEvents(): Observable<Events[]> {
    // Using direct HttpClient instead of the auto-generated service with the wrong endpoint
    return this.httpClient.get<Events[]>(`${this.apiBaseUrl}/logfiles/unified-event-log`);
  }
  
  // Mapping from backend events to frontend SecurityEvents
  private mapBackendEventsToSecurityEvents(backendEvents: Events[]): SecurityEvent[] {
    if (!backendEvents || !Array.isArray(backendEvents)) {
      console.warn('Unexpected response format for events:', backendEvents);
      return [];
    }
    
    return backendEvents.map(backendEvent => {
      // Format date for display
      const eventDate = new Date(backendEvent.timestamp);
      const formattedDate = this.formatDate(eventDate);
      
      // Calculate relative time
      const relativeTime = this.calculateRelativeTime(eventDate);
      
      // Map status based on severity
      const status = this.mapSeverityToStatus(backendEvent.severity);
      
      return {
        id: backendEvent.id,
        date: formattedDate,
        relativeTime: relativeTime,
        event: backendEvent.event_type,
        status: status,
        ips: backendEvent.source_ips || []
      };
    });
  }
  // Helper method for date formatting (DD.MM.YYYY)
  private formatDate(date: Date): string {
    const day = date.getDate().toString().padStart(2, '0');
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const year = date.getFullYear();
    return `${day}.${month}.${year}`;
  }
  // Helper method for calculating relative time
  private calculateRelativeTime(date: Date): string {
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);
    if (diffDays > 0) {
      return `(vor ${diffDays} ${diffDays === 1 ? 'Tag' : 'Tagen'})`;
    } else if (diffHours > 0) {
      return `(vor ${diffHours} ${diffHours === 1 ? 'Stunde' : 'Stunden'})`;
    } else {
      return `(vor ${diffMins} ${diffMins === 1 ? 'Minute' : 'Minuten'})`;
    }
  }
  // Helper method for mapping severity levels
  private mapSeverityToStatus(severity: string): 'Kritisch' | 'Warnung' | 'Normal' {
    severity = severity.toLowerCase();
    if (severity.includes('critical') || severity.includes('kritisch') || severity.includes('high')) {
      return 'Kritisch';
    } else if (severity.includes('warning') || severity.includes('warnung') || severity.includes('medium')) {
      return 'Warnung';
    } else {
      return 'Normal';
    }
  }
  getCriticalEvents(): SecurityEvent[] {
    return this.events.filter(event => event.status === 'Kritisch');
  }
  getCriticalEventsCount(): number {
    return this.getCriticalEvents().length;
  }
  
  getAllEvents(): SecurityEvent[] {
    return this.events;
  }
  
  refreshEvents(): Observable<SecurityEvent[]> {
    return this.loadEventsFromBackend();
  }
}