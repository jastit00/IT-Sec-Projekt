import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ChartOneComponent } from './chart-one.component';

describe('ChartOneComponent', () => {
  let component: ChartOneComponent;
  let fixture: ComponentFixture<ChartOneComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ChartOneComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ChartOneComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
