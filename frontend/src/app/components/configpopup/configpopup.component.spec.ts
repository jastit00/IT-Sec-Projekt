import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ConfigpopupComponent } from './configpopup.component';

describe('ConfigpopupComponent', () => {
  let component: ConfigpopupComponent;
  let fixture: ComponentFixture<ConfigpopupComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ConfigpopupComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ConfigpopupComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
