import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CriticalEventsComponent } from './critical-events.component';

describe('CriticalEventsComponent', () => {
  let component: CriticalEventsComponent;
  let fixture: ComponentFixture<CriticalEventsComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [CriticalEventsComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(CriticalEventsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
