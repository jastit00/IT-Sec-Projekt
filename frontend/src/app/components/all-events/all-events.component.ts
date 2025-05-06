import { Component } from '@angular/core';
import { EventService } from '../../services/event-service';

@Component({
  selector: 'app-all-events',
  templateUrl: './all-events.component.html',
  styleUrls: ['./all-events.component.scss']
})
export class AllEventsComponent {
  events: { id: number; date: string; relativeTime: string; event: string; status: string; ips: string[]; }[];
  constructor(private eventService: EventService) { 
    this.events = this.eventService.events;
  }
}
