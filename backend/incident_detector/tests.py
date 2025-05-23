from django.test import TestCase
from django.utils import timezone
from .models import User_Login, Incident
from .services import detect_bruteforce, detect_incidents
from datetime import timedelta

class BruteForceDetectionTests(TestCase):

    def setUp(self):
        self.now = timezone.now()

    def create_logins(self, count, minutes_apart=0.3, success_on_last=False):
        username = "testuser"
        ip = "192.168.0.1"
        for i in range(count):
            User_Login.objects.create(
                username=username,
                  ip_address=ip,
                result="success" if (success_on_last and i == count - 1) else "fail",
                timestamp=self.now + timedelta(minutes=i * minutes_apart)
            )

    def test_no_bruteforce_if_too_few_attempts(self):
        self.create_logins(5)
        result = detect_bruteforce()
        self.assertEqual(result["bruteforce"], 0)
        self.assertEqual(Incident.objects.count(), 0)

    def test_detect_bruteforce_attempt(self):
        self.create_logins(13)
        result = detect_bruteforce()
        self.assertEqual(result["bruteforce"], 1)
        self.assertEqual(Incident.objects.count(), 1)

    def test_ignore_attempts_outside_time_window(self):
        self.create_logins(13, minutes_apart=1)  # 13 mins apart > 5
        result = detect_bruteforce()
        self.assertEqual(result["bruteforce"], 0)

    def test_successful_last_attempt_changes_reason(self):
        self.create_logins(13, success_on_last=True)
        detect_bruteforce()
        incident = Incident.objects.first()
        self.assertIn("Successful", incident.reason)

    def test_detect_incidents_wrapper(self):
        self.create_logins(13)
        result = detect_incidents()
        self.assertIn("incidents", result)
        self.assertEqual(result["incidents"]["bruteforce"], 1)

    def test_duplicate_incident_is_not_created(self):
        self.create_logins(13)
        detect_bruteforce()
        detect_bruteforce()  # call twice
        self.assertEqual(Incident.objects.count(), 1)

class ConcurrentLoginsDetectionTest(TestCase):
    
    def test_single_clear_attack_detected(self):
        # create the specific entries
        UserLogin.objects.create(timestamp="2025-03-27 11:49:54.508+01", username="admin", src_ip_address="192.168.0.40", terminal="cda8", result="success")
        UserLogin.objects.create(timestamp="2025-03-27 11:49:54.508+01", username="testuser", src_ip_address="192.168.0.38", terminal="abcd", result="success")
        UserLogout.objects.create(timestamp="2025-03-27 11:49:54.508+01", username="admin", terminal="cda8")
        UserLogin.objects.create(timestamp="2025-03-27 11:49:54.508+01", username="admin", src_ip_address="192.168.0.40", terminal="cda9", result="success")
        UserLogout.objects.create(timestamp="2025-03-27 11:49:54.508+01", username="admin", terminal="cda9")
        UserLogin.objects.create(timestamp="2025-03-27 11:49:54.508+01", username="testuser", src_ip_address="192.168.0.39", terminal="abc0", result="success")
        
        # test
        result=detect_concurrent_logins()
        self.assertEqual(result["concurrent_logins"],1)
        self.assertEqual(ConcurrentLoginIncident.objects.count(),1)

    def test_multiple_clear_attack_detected(self):
        # create the specific entries
        UserLogin.objects.create(timestamp="2025-03-27 11:49:54.508+01", username="admin", src_ip_address="109.108.107.10", terminal="cdi8", result="success")
        UserLogin.objects.create(timestamp="2025-03-27 11:49:54.508+01", username="admin", src_ip_address="109.108.108.10", terminal="cdj8", result="success")
        UserLogin.objects.create(timestamp="2025-03-27 11:49:54.508+01", username="admin", src_ip_address="110.120.30.254", terminal="cdh9", result="success")
        UserLogin.objects.create(timestamp="2025-03-27 11:49:54.508+01", username="admin", src_ip_address="200.168.10.10", terminal="cdc8", result="success")
        
        # test
        result=detect_concurrent_logins()
        self.assertEqual(result["concurrent_logins"],3)
        self.assertEqual(ConcurrentLoginIncident.objects.count(),3)
