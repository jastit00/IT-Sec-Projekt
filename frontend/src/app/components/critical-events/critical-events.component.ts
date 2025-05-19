import { Component, Input } from '@angular/core';
import { EventService } from '../../services/event-service';

@Component({
  selector: 'app-critical-events',
  templateUrl: './critical-events.component.html',
  styleUrls: ['./critical-events.component.scss']
})

export class CriticalEventsComponent {
  events: { id: number; date: string; relativeTime: string; event: string; status: string; ips: string[]; }[];
  constructor(private eventService: EventService) { 
    this.events = this.eventService.events;
  }
}