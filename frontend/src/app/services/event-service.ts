import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, map, catchError, of, tap, finalize, Subscription } from 'rxjs';
//Import API
import { DefaultService } from '../api-client';
import { ChartUpdateService } from './chart-update.service';
//and Events interface
import { Events } from '../models/events.model';

import { environment } from '../../environments/environment';

//frontend interface for security events
export interface SecurityEvent {
  id: number; // Not optional, always required
  date: string;
  event: string;
  status: 'Critical' | 'Warning' | 'Normal';
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
  private updateService = inject(ChartUpdateService);
  private apiBaseUrl = `${environment.backendUrl}/api`; // base URL
  updateSubscription!: Subscription;
  eventSubscription!: Subscription;
  
  //current events from API call
  events: SecurityEvent[] = [];
  loading = false;

  constructor() {
    // Load data on initialization
    this.eventSubscription = this.loadEventsFromBackend().subscribe(); // Direct subscribe, otherwise it won't load

    this. updateSubscription = this.updateService.updateChart$.subscribe(() => {
    this.refreshEvents()
    
  });
  }

  ngOnDestroy(): void {
    this.eventSubscription.unsubscribe();
    this.updateSubscription.unsubscribe();
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
    // Using the correct endpoint from the available Django URLs
    return this.httpClient.get<Events[]>(`${this.apiBaseUrl}/logfiles/unified-event-log/`);
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
      
      //map status based on severity
      const status = this.mapSeverityToStatus(backendEvent.severity);
      
      //generate description 
      const description = this.generateDescription(backendEvent);
      
      //extract all IP addresses 
      const ips = this.extractIPs(backendEvent);
      
      return {
        id: backendEvent.id ?? Math.floor(Math.random() * 10000), // Ensure id is always a number, generate random if undefined
        date: formattedDate,
        event: this.getDisplayEventType(backendEvent), 
        status: status,
        ips: ips,
        description: description
      };
    });
  }

  //description based on event type
  private generateDescription(event: Events): string {
    const eventType = this.getDisplayEventType(event).toLowerCase();
    
    switch (eventType) {
      case 'network packet':
      case 'network packets':
        const packetInfo = [];
        if (event.protocol) packetInfo.push(`Protocol: ${event.protocol}`);
        if (event.count) packetInfo.push(`Count: ${event.count}`);
        if (event.packets) packetInfo.push(`Packets: ${event.packets}`);
        if (event.timeDelta) packetInfo.push(`Time Window: ${event.timeDelta}`);
        if (event.dst_ip_address) packetInfo.push(`Destination: ${event.dst_ip_address}`);
        if (event.reason) packetInfo.push(`Reason: ${event.reason}`);
        return packetInfo.length > 0 ? packetInfo.join(' | ') : '';
        
      case 'logout':
        // For logout events, show result and username if available
        const logoutInfo = [];
        if (event.username) logoutInfo.push(`User: ${event.username}`);
        if (event.result) {
          const resultText = event.result === 'failed' ? 'Failed' : 
                            event.result === 'success' || event.result === 'successful' ? 'Successful' : event.result;
          logoutInfo.push(`Status: ${resultText}`);
        }
        return logoutInfo.join(' | ');
        
      case 'login':
        // For login events, show result and username if available
        const loginInfo = [];
        if (event.username) loginInfo.push(`User: ${event.username}`);
        if (event.result) {
          const resultText = event.result === 'failed' ? 'Failed' : 
                            event.result === 'success' || event.result === 'successful' ? 'Successful' : event.result;
          loginInfo.push(`Status: ${resultText}`);
        }
        return loginInfo.join(' | ');
        
      case 'incident':
        // For incidents, show incident_type + src_ip_address + reason
        const incidentInfo = [];
        if (event.incident_type) {
          const incidentTypeText = event.incident_type.toLowerCase() === 'dos' ? 'DoS Attack' : event.incident_type;
          incidentInfo.push(`Type: ${incidentTypeText}`);
        }
        if (event.src_ip_address) incidentInfo.push(`Source IP: ${event.src_ip_address}`);
        if (event.reason) incidentInfo.push(`Reason: ${event.reason}`);
        return incidentInfo.join(' | ');
        
      case 'config change':
        // For config changes (including incident events with configchange type)
        const configInfo = [];
        
        // If it's an incident with configchange, show the reason and source IP
        if (event.event_type === 'incident' && event.incident_type === 'configchange') {
          if (event.src_ip_address) configInfo.push(`Source IP: ${event.src_ip_address}`);
          if (event.reason) configInfo.push(`Details: ${event.reason}`);
        } else {
          // Regular config change events
          if (event.action) {
            const actionText = event.action.toLowerCase() === 'update' ? 'Update' : event.action;
            configInfo.push(`Action: ${actionText}`);
          }
          if (event.key && event.value) configInfo.push(`${event.key}: ${event.value}`);
          if (event.terminal) configInfo.push(`User: ${event.terminal}`);
          if (event.result) {
            const resultText = event.result === 'failed' ? 'Failed' : 
                             event.result === 'success' ? 'Successful' : event.result;
            configInfo.push(`Status: ${resultText}`);
          }
        }
        return configInfo.join(' | ');
        
      default:
        return '';
    }
  }

  // Helper method to determine display event type
  private getDisplayEventType(event: Events): string {
    // If it's an incident with configchange type, display it as Config Change
    if (event.event_type === 'incident' && event.incident_type === 'configchange') {
      return 'Config Change';
    }
    return event.event_type;
  }

  //date formatting with time and seconds (English format)
  private formatDate(date: Date): string {
    const day = date.getDate().toString().padStart(2, '0');
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const year = date.getFullYear();
    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    const seconds = date.getSeconds().toString().padStart(2, '0');
    return `${month}/${day}/${year} ${hours}:${minutes}:${seconds}`;
  }

  private mapSeverityToStatus(severity: string): 'Critical' | 'Warning' | 'Normal' {
    if (!severity) return 'Normal';
    
    severity = severity.toLowerCase();
    if (severity.includes('critical') || severity.includes('kritisch') || severity.includes('high')) {
      return 'Critical';
    } else if (severity.includes('warning') || severity.includes('warnung') || severity.includes('medium')) {
      return 'Warning';
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
    
    //check dst_ip_address for network packets and incidents
    if (event.dst_ip_address && typeof event.dst_ip_address === 'string' && event.dst_ip_address.trim() !== '') {
      const ip = event.dst_ip_address.trim();
      if (!ips.includes(ip)) {
        ips.push(ip);
      }
    }
    
    //check IP in details object if present
    if (event.details) {
      if (event.details.src_ip_address && typeof event.details.src_ip_address === 'string') {
        const ip = event.details.src_ip_address.trim();
        if (ip !== '' && !ips.includes(ip)) {
          ips.push(ip);
        }
      }
      
      if (event.details.dst_ip_address && typeof event.details.dst_ip_address === 'string') {
        const ip = event.details.dst_ip_address.trim();
        if (ip !== '' && !ips.includes(ip)) {
          ips.push(ip);
        }
      }
      
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
    return this.events.filter(event => event.status === 'Critical');
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