import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ConfigChangesComponent } from './config-changes.component';

describe('ConfigChangesComponent', () => {
  let component: ConfigChangesComponent;
  let fixture: ComponentFixture<ConfigChangesComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ConfigChangesComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ConfigChangesComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
