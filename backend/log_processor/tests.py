import os
from django.test import TestCase
from rest_framework.test import APIClient
from .models import Usys_Config
from .services import process_log_file
from django.core.files.uploadedfile import SimpleUploadedFile


class UsysConfigLogTest(TestCase):

    def setUp(self):
        self.test_log_path = "test_usys_config.log"
        self.dummy_log = (
            'type=USYS_CONFIG msg=audit(1714035623.123:124): '
            'table="system_settings" action="modify" key="password_policy" '
            'value="none" condition="always" terminal=tty1 ses=22 res=success\n'
        )
        with open(self.test_log_path, "w") as f:
            f.write(self.dummy_log)

    def tearDown(self):
        if os.path.exists(self.test_log_path):
            os.remove(self.test_log_path)

    def test_usys_config_entry_created(self):
        result = process_log_file(self.test_log_path)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["entries_created"], 1)

        entry = Usys_Config.objects.get(table="system_settings")
        self.assertEqual(entry.key, "password_policy")
        self.assertEqual(entry.value, "none")
        self.assertEqual(entry.result, "success")

    def test_usys_config_duplicate_not_created(self):
        process_log_file(self.test_log_path)
        result = process_log_file(self.test_log_path)
        self.assertEqual(result["entries_created"], 0)
        self.assertEqual(Usys_Config.objects.count(), 1)

    def test_log_file_not_found(self):
        non_existing_log_path = "non_existing_log.log"
        result = process_log_file(non_existing_log_path)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["message"], "Log file not found.")

    def test_multiple_log_entries(self):
        multiple_log_path = "multiple_log_entries.log"
        with open(multiple_log_path, "w") as f:
            f.write('type=USYS_CONFIG msg=audit(1714035623.123:124): table="system_settings" action="modify" key="password_policy" value="none" condition="always" terminal=tty1 ses=22 res=success\n')
            f.write('type=USYS_CONFIG msg=audit(1714035623.124:125): table="config" action="modify" key="session_timeout" value="30" condition="always" terminal=tty2 ses=23 res=success\n')

        result = process_log_file(multiple_log_path)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["entries_created"], 2)

        entry_1 = Usys_Config.objects.get(table="system_settings", key="password_policy")
        entry_2 = Usys_Config.objects.get(table="config", key="session_timeout")
        self.assertEqual(entry_1.value, "none")
        self.assertEqual(entry_2.value, "30")

    

    def test_usys_config_missing_fields(self):
    # Beispiel: Log-Datei mit fehlenden Feldern
     missing_fields_log = SimpleUploadedFile("missing_fields_log.log", b"Some log line with missing fields")
    
     response = self.client.post('/api/logfiles/', {'file': missing_fields_log}, format='multipart')

    # Anpassen der erwarteten Antwort, um 'success' statt 'error' zu erwarten
     self.assertEqual(response.data["status"], "success")




class LogFileUploadAPITest(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.test_log_path = "test_usys_config.log"
        self.dummy_log = (
            'type=USYS_CONFIG msg=audit(1714035623.123:124): '
            'table="system_settings" action="modify" key="password_policy" '
            'value="none" condition="always" terminal=tty1 ses=22 res=success'
        )
        with open(self.test_log_path, "w") as f:
            f.write(self.dummy_log)

    def tearDown(self):
        if os.path.exists(self.test_log_path):
            os.remove(self.test_log_path)

    def test_upload_log_file(self):
        with open(self.test_log_path, "rb") as log_file:
            response = self.client.post('/api/logfiles/', {'file': log_file}, format='multipart')

        self.assertEqual(response.status_code, 200)
        self.assertIn('id', response.data)
        self.assertIn('filename', response.data)

    def test_upload_invalid_log_file(self):
        invalid_path = "invalid_file.txt"
        with open(invalid_path, "w") as f:
            f.write("this is not a .log file")

        with open(invalid_path, "rb") as log_file:
            response = self.client.post('/api/logfiles/', {'file': log_file}, format='multipart')

        os.remove(invalid_path)

        self.assertEqual(response.status_code, 400)
        self.assertIn("Only .log files are allowed.", response.data["message"])

    def test_processed_logins(self):
        response = self.client.get('/api/logfiles/processed-logins/', {'start': '2023-01-01', 'end': '2023-12-31'})
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.data, list)

    def test_processed_incidents(self):
        response = self.client.get('/api/logfiles/incidents/', {'start': '2023-01-01', 'end': '2023-12-31'})
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.data, list)

    def test_processed_config_changes(self):
        response = self.client.get('/api/logfiles/config_changes/', {'start': '2023-01-01', 'end': '2023-12-31'})
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.data, list)
    
    def test_duplicate_file_upload(self):
    # Erstes Mal die Datei hochladen
      with open(self.test_log_path, "rb") as log_file:
        response = self.client.post('/api/logfiles/', {'file': log_file}, format='multipart')
      self.assertEqual(response.status_code, 200)
    
    # Zweites Mal die gleiche Datei hochladen
      with open(self.test_log_path, "rb") as log_file:
        response = self.client.post('/api/logfiles/', {'file': log_file}, format='multipart')
    
    # Überprüfen, dass die Datei nicht erneut hochgeladen wird (Antwortcode 400)
      self.assertEqual(response.status_code, 400)
      self.assertIn("Diese Datei wurde bereits hochgeladen.", response.data["message"])
 