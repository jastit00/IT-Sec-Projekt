import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ChartEightComponent } from './chart-eight.component';

describe('ChartEightComponent', () => {
  let component: ChartEightComponent;
  let fixture: ComponentFixture<ChartEightComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ChartEightComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ChartEightComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
