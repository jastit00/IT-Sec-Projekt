import { ComponentFixture, TestBed } from '@angular/core/testing';
import { HeaderComponent } from './header.component';
import { By } from '@angular/platform-browser';
import { ElementRef } from '@angular/core';

describe('HeaderComponent', () => {
  let component: HeaderComponent;
  let fixture: ComponentFixture<HeaderComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HeaderComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(HeaderComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should display the dashboard title', () => {
    const titleElement = fixture.debugElement.query(By.css('nav')).nativeElement;
    expect(titleElement.textContent).toContain('Dashboard');
  });

  it('should contain critical events button', () => {
    const criticalEventsButton = fixture.debugElement.query(By.css('.critical-events-btn')).nativeElement;
    expect(criticalEventsButton.textContent).toContain('Critical Events');
  });

  it('should contain upload files button', () => {
    const uploadButton = fixture.debugElement.query(By.css('.upload-btn')).nativeElement;
    expect(uploadButton.textContent).toContain('Upload Files');
  });

  it('should contain logout button', () => {
    const logoutButton = fixture.debugElement.query(By.css('.logout-btn')).nativeElement;
    expect(logoutButton.textContent).toContain('Logout');
  });
  it('should trigger file input when upload button is clicked', () => {
    // Mocken des echten Klicks
    const fileInput = { click: jasmine.createSpy('click') };
    spyOn(document, 'querySelector').and.returnValue(fileInput as any); // Simulieren des file input
  
    component.openFileUpload(); // Öffne Datei-Upload
    expect(fileInput.click).toHaveBeenCalled(); // Überprüfe ob Klick ausgelöst wurde
  });
  
  it('should handle file selection', () => {
    spyOn(console, 'log'); // Überwache console.log
    const mockEvent = {
      target: {
        files: ['mockFile'] // Mock-Datei
      }
    };
  
    component.onFileSelected(mockEvent as unknown as Event); // Simuliere die Auswahl von Dateien
    expect(console.log).toHaveBeenCalledWith('Dateien ausgewählt:', ['mockFile']); // Überprüfe das Log
  });
 
});