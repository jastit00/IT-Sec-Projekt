import { ComponentFixture, TestBed } from '@angular/core/testing';

import { TeapotComponent } from './teapot.component';

describe('TeapotComponent', () => {
  let component: TeapotComponent;
  let fixture: ComponentFixture<TeapotComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TeapotComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(TeapotComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
