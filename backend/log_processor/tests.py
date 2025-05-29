import os
from django.test import TestCase
from rest_framework.test import APIClient
from django.core.files.uploadedfile import SimpleUploadedFile
from .models import UsysConfig
from .services import process_log_file


TEST_LOG_PATH = "test_usys_config.log"
DUMMY_LOG_CONTENT = (
    'type=USYS_CONFIG msg=audit(1714035623.123:124): '
    'table="system_settings" action="modify" key="password_policy" '
    'value="none" condition="always" terminal=tty1 ses=22 res=success\n'
)


class UsysConfigLogTest(TestCase):
   
    def setUp(self):
        self.client = APIClient()
        self._create_test_log_file(TEST_LOG_PATH, DUMMY_LOG_CONTENT)
        
        self.addCleanup(self._cleanup_file, TEST_LOG_PATH)

   
    def _create_test_log_file(self, filename, content):
        with open(filename, "w") as f:
            f.write(content)


    def _cleanup_file(self, filename):
        if os.path.exists(filename):
            os.remove(filename)

    def test_process_log_file_creates_entry(self):
        result = process_log_file(TEST_LOG_PATH)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["entries_created"], 1)

        entry = UsysConfig.objects.get(table="system_settings")
        self.assertEqual(entry.key, "password_policy")
        self.assertEqual(entry.value, "none")
        self.assertEqual(entry.result, "success")

    def test_process_log_file_prevents_duplicates(self):
        process_log_file(TEST_LOG_PATH)
        result = process_log_file(TEST_LOG_PATH)
        self.assertEqual(result["entries_created"], 0)
        self.assertEqual(UsysConfig.objects.count(), 1)

    def test_process_log_file_not_found(self):
        non_existing_log_path = "non_existing_log.log"
        result = process_log_file(non_existing_log_path)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["message"], "Log file not found.")

    def test_process_multiple_log_entries(self):
        multiple_log_path = "multiple_log_entries.log"
        content = (
            'type=USYS_CONFIG msg=audit(1714035623.123:124): table="system_settings" '
            'action="modify" key="password_policy" value="none" condition="always" '
            'terminal=tty1 ses=22 res=success\n'
            'type=USYS_CONFIG msg=audit(1714035623.124:125): table="config" '
            'action="modify" key="session_timeout" value="30" condition="always" '
            'terminal=tty2 ses=23 res=success\n'
        )
        self._create_test_log_file(multiple_log_path, content)
        self.addCleanup(self._cleanup_file, multiple_log_path)

        result = process_log_file(multiple_log_path)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["entries_created"], 2)

        entry_1 = UsysConfig.objects.get(table="system_settings", key="password_policy")
        entry_2 = UsysConfig.objects.get(table="config", key="session_timeout")
        self.assertEqual(entry_1.value, "none")
        self.assertEqual(entry_2.value, "30")

    def test_process_log_file_with_missing_fields(self):
 
        missing_fields_log = SimpleUploadedFile("missing_fields_log.log", b"Some log line with missing fields")
        response = self.client.post('/api/logfiles/', {'file': missing_fields_log}, format='multipart')
        self.assertEqual(response.data["status"], "success")


class LogFileUploadAPITest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self._create_test_log_file(TEST_LOG_PATH, DUMMY_LOG_CONTENT)
        self.addCleanup(self._cleanup_file, TEST_LOG_PATH)

    def _create_test_log_file(self, filename, content):
        with open(filename, "w") as f:
            f.write(content)

    def _cleanup_file(self, filename):
        if os.path.exists(filename):
            os.remove(filename)

    def test_upload_log_file(self):
        with open(TEST_LOG_PATH, "rb") as log_file:
            response = self.client.post('/api/logfiles/', {'file': log_file}, format='multipart')

        self.assertEqual(response.status_code, 200)
        self.assertIn('id', response.data)
        self.assertIn('filename', response.data)

    def test_upload_invalid_log_file(self):
        invalid_path = "invalid_file.txt"
        self._create_test_log_file(invalid_path, "this is not a .log file")
        self.addCleanup(self._cleanup_file, invalid_path)

        with open(invalid_path, "rb") as log_file:
            response = self.client.post('/api/logfiles/', {'file': log_file}, format='multipart')

        self.assertEqual(response.status_code, 400)
        self.assertIn("Only .log files are allowed.", response.data["message"])

    def test_processed_logins(self):
        response = self.client.get('/api/logfiles/processed-logins/', {'start': '2023-01-01', 'end': '2023-12-31'})
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.data, list)

    def test_processed_config_changes(self):
        response = self.client.get('/api/logfiles/config-changes/', {'start': '2023-01-01', 'end': '2023-12-31'})
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.data, list)

    def test_duplicate_file_upload_returns_400(self):
  
        with open(TEST_LOG_PATH, "rb") as log_file:
            response = self.client.post('/api/logfiles/', {'file': log_file}, format='multipart')
            self.assertEqual(response.status_code, 200)

        
        with open(TEST_LOG_PATH, "rb") as log_file:
            response = self.client.post('/api/logfiles/', {'file': log_file}, format='multipart')
            self.assertEqual(response.status_code, 400)
            self.assertIn("Diese Datei wurde bereits hochgeladen.", response.data["message"])
