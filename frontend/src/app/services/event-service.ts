import { Injectable } from '@angular/core';

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
  events: SecurityEvent[] = [
    {
      id: 1,
      date: '24.04.2025',
      relativeTime: '(vor 5 Minuten)',
      event: 'Unauthorized Access',
      status: 'Kritisch',
      ips: ['192.168.1.45', '203.0.113.12', '198.51.100.78']
    },
    {
      id: 2,
      date: '23.04.2025',
      relativeTime: '(vor 8 Stunden)',
      event: 'DDos Verdacht',
      status: 'Warnung',
      ips: ['192.168.1.36', '45.33.32.156']
    },
    {
      id: 3,
      date: '22.04.2025',
      relativeTime: '(vor 2 Tagen)',
      event: 'Admin Login',
      status: 'Normal',
      ips: []
    },
    {
      id: 4,
      date: '21.04.2025',
      relativeTime: '(vor 3 Tagen)',
      event: 'Failed Login',
      status: 'Warnung',
      ips: ['192.168.1.22', '172.16.254.1', '10.0.0.145']
    },
  ];

  // Method to get critical events
  getCriticalEvents(): SecurityEvent[] {
    return this.events.filter(event => event.status === 'Kritisch');
  }

  // Method to count critical events
  getCriticalEventsCount(): number {
    return this.getCriticalEvents().length;
  }
}