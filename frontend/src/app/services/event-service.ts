import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, map, catchError, of, tap, finalize } from 'rxjs';
//Import API
import { DefaultService } from '../api-client';
//und Events interface auch
import { Events } from '../models/events.model';

//frontend interface für die security events
export interface SecurityEvent {
  id: number;
  date: string;
  relativeTime: string;
  event: string;
  status: 'Kritisch' | 'Warnung' | 'Normal';
  ips: string[];
  description: string;
}

@Injectable({
  providedIn: 'root'
})
export class EventService {
  // Use inject instead of constructor injection
  private defaultService = inject(DefaultService);
  private httpClient = inject(HttpClient);
  private apiBaseUrl = 'http://localhost:8000/api'; // base URL
  
  //aktuelle  events von API call
  events: SecurityEvent[] = [];
  loading = false;

  constructor() {
    // Load data on initialization
    this.loadEventsFromBackend().subscribe(); // Direkt subscribe, sonst lädt es nicht
  }

  //method to load data from backend
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
      //format date for display
      const eventDate = new Date(backendEvent.timestamp);
      const formattedDate = this.formatDate(eventDate);
      
      //calculate relative time
      const relativeTime = this.calculateRelativeTime(eventDate);
      
      //map status based on severity
      const status = this.mapSeverityToStatus(backendEvent.severity);
      
      //generate description 
      const description = this.generateDescription(backendEvent);
      
      //extract all IP addresses 
      const ips = this.extractIPs(backendEvent);
      
      console.log(`Event ${backendEvent.id} (${backendEvent.event_type}):`, {
        source_ips: backendEvent.source_ips,
        src_ip_address: backendEvent.src_ip_address,
        extracted_ips: ips,
        details: backendEvent.details
      });
      
      return {
        id: backendEvent.id,
        date: formattedDate,
        relativeTime: relativeTime,
        event: backendEvent.event_type,
        status: status,
        ips: ips,
        description: description
      };
    });
  }

  //description based on event type
  private generateDescription(event: Events): string {
    switch (event.event_type.toLowerCase()) {
      case 'network packet':
        return ''; //nw packet geht ja noch nicht
      case 'logout':
        return event.result || '';
      case 'login':
        return event.result || '';
      case 'incident':
        //incident_type + src_ip_address + reason
        return `${event.incident_type || ''};${event.src_ip_address || ''};${event.reason || ''}`.trim();
      case 'config change':
        //action + result
        return `${event.action || ''} ${event.result || ''}`.trim();
      default:
        return '';
    }
  }

  //date formatierung
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
  
  // Helper method to extract IPs from event
  private extractIPs(event: Events): string[] {
    const ips: string[] = [];
    
    //check if the event has source_ips
    if (event.source_ips && Array.isArray(event.source_ips)) {
      event.source_ips.forEach(ip => {
        if (ip && typeof ip === 'string' && ip.trim() !== '') {
          ips.push(ip.trim());
        }
      });
    }
    
    //check src_ip_address 
    if (event.src_ip_address && typeof event.src_ip_address === 'string' && event.src_ip_address.trim() !== '') {
      const ip = event.src_ip_address.trim();
      if (!ips.includes(ip)) {
        ips.push(ip);
      }
    }
    
    //check IP
    if (event.event_type.toLowerCase() === 'incident' && event.details) {
      if (event.details.src_ip_address && typeof event.details.src_ip_address === 'string') {
        const ip = event.details.src_ip_address.trim();
        if (ip !== '' && !ips.includes(ip)) {
          ips.push(ip);
        }
      }
      
      //check ipAddress
      if (event.details.ipAddress && typeof event.details.ipAddress === 'string') {
        const ip = event.details.ipAddress.trim();
        if (ip !== '' && !ips.includes(ip)) {
          ips.push(ip);
        }
      }
    }
    
    return ips;
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