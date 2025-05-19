import { Component } from '@angular/core';
import { EventService, SecurityEvent } from '../../services/event-service';

@Component({
  selector: 'app-all-events',
  templateUrl: './all-events.component.html',
  styleUrls: ['./all-events.component.scss']
})
export class AllEventsComponent {
  events: SecurityEvent[];

  constructor(private eventService: EventService) {
    this.events = this.eventService.getAllEvents();
  }
}
