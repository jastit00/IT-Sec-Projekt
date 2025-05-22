import os
import requests

# Pfad zum Ordner mit den Log-Dateien
log_dir = r"D:\UNI\ITSec_Projekt\Backend\IT-Sec-Projekt-1\logs"  # anpassen

upload_url = "http://localhost:8000/api/logfiles/"

for filename in os.listdir(log_dir):
    file_path = os.path.join(log_dir, filename)

    if os.path.isfile(file_path):
        print(f"📤 Lade hoch: {filename}")
        with open(file_path, 'rb') as f:
            files = {'file': (filename, f)}
            data = {
                'source': 'testscript',
                'uploaded_by_user': 'testuser'
            }
            response = requests.post(upload_url, files=files, data=data)

        if response.status_code in [200, 201]:
            try:
                resp_json = response.json()
                print(f"✅ Erfolgreich hochgeladen: {filename}")
                print(f"   ID: {resp_json.get('id')}")
                print(f"   Status: {resp_json.get('status')}")
                print(f"   Entries created: {resp_json.get('entries_created')}")
                print(f"   Incidents created: {resp_json.get('incidents_created_total')}") 
        
                print(f"   incident_counts: {resp_json.get('incident_counts')}") 
            except Exception as e:
                print(f"✅ Erfolgreich hochgeladen: {filename} (konnte Antwort nicht lesen)")
        else:
            print(f"❌ Fehler bei {filename}: {response.status_code} - {response.text}")
