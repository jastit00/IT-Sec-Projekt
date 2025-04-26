
    
import os
from django.test import TestCase
from .models import Usys_Config
from .services import process_log_file  

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
        # 🧹 Datei nach dem Test löschen
        if os.path.exists(self.test_log_path):
            os.remove(self.test_log_path)

    def test_usys_config_entry_created(self):
        result = process_log_file(self.test_log_path)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["entries_created"], 1)

        # 🧪 Datenbankeintrag prüfen
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
        # Test für eine nicht vorhandene Datei
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

        # Überprüfe, ob beide Einträge korrekt in der DB gespeichert wurden
        entry_1 = Usys_Config.objects.get(table="system_settings", key="password_policy")
        entry_2 = Usys_Config.objects.get(table="config", key="session_timeout")
        self.assertEqual(entry_1.value, "none")
        self.assertEqual(entry_2.value, "30")

    def test_invalid_log_line(self):
        invalid_log_path = "invalid_log.log"
        with open(invalid_log_path, "w") as f:
            f.write('invalid_line_without_proper_format\n')
            result = process_log_file(invalid_log_path)
        self.assertEqual(result["status"], "error")
        self.assertIn("Invalid log format", result["message"])


    def test_usys_config_missing_fields(self):
        missing_field_log_path = "missing_field_log.log"
        with open(missing_field_log_path, "w") as f:
            f.write('type=USYS_CONFIG msg=audit(1714035623.123:124): table="system_settings" action="modify" key="password_policy" value="none" res=success\n')  # "condition" fehlt
        result = process_log_file(missing_field_log_path)
        self.assertEqual(result["status"], "error")
        self.assertIn("Missing field 'condition'", result["message"])
