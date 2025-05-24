from django.test import TestCase
from django.utils import timezone
from .models import UserLogin, UserLogout, Incident, ConcurrentLoginIncident
from .services import detect_bruteforce, detect_incidents, detect_concurrent_logins

from django.conf import settings
import os
from collections import defaultdict
import re
import tempfile
import hashlib
from datetime import datetime

class CreateEntries():
    def make_entries(self, file_to_use):
        # Construct path to log file
        log_file_path = os.path.join(settings.BASE_DIR,'incident_detector','tests_logs',file_to_use)
        # Normalize the path to handle any ../ properly
        normalized_log_file_path = os.path.normpath(log_file_path)
        self.process_log_file(normalized_log_file_path)
    
    def process_log_file(self, file_path):
        packet_counts = defaultdict(int)
        with open(file_path, 'r') as log_file:
            for line in log_file:
                line = line.strip()
                if "type=USER_LOGIN" in line:
                    timestamp = self.extract_timestamp(line)
                    if not timestamp:
                        continue
                    username = self.extract_match(r'acct="([^"]*)"', line)
                    src_ip_address = self.extract_match(r'addr=([^\s]*)', line)
                    result = self.extract_match(r'res=([^\'\s]*)', line)
                    terminal = self.extract_match(r'terminal=([^\s]*)', line)
                    if not UserLogin.objects.filter(timestamp=timestamp,username=username,src_ip_address=src_ip_address,result=result,terminal=terminal).exists():
                        UserLogin.objects.create(timestamp=timestamp,username=username,src_ip_address=src_ip_address,result=result,terminal=terminal,severity="normal" if result == "success" else "warning")
                elif "type=USER_LOGOUT" in line or "type=USER_END" in line:
                    timestamp = self.extract_timestamp(line)
                    if not timestamp:
                        continue
                    username = self.extract_match(r'acct="([^"]*)"', line)
                    result = self.extract_match(r'res=([^\'\s]*)', line)
                    terminal = self.extract_match(r'terminal=([^\s]*)', line)
                    if not UserLogout.objects.filter(timestamp=timestamp,username=username,result=result,terminal=terminal).exists():
                        UserLogout.objects.create(timestamp=timestamp,username=username,result=result,terminal=terminal,severity="normal" if result == "success" else "warning")
                elif "type=USYS_CONFIG" in line:
                    timestamp = self.extract_timestamp(line)
                    if not timestamp:
                        continue
                    table = self.extract_match(r'table="([^"]*)"', line)
                    action = self.extract_match(r'action="([^"]*)"', line)
                    key = self.extract_match(r'key="([^"]*)"', line)
                    value = self.extract_match(r'value="([^"]*)"?', line)
                    condition = self.extract_match(r'condition="([^"]*)"', line)
                    terminal = self.extract_match(r'terminal\s*=\s*([^\s]*)', line)
                    result = self.extract_match(r'res\s*=\s*([^\'\s]*)', line)
                    if not UsysConfig.objects.filter(timestamp=timestamp,table=table,action=action,key=key,value=value,condition=condition,terminal=terminal,result=result).exists():
                        UsysConfig.objects.create(timestamp=timestamp,table=table,action=action,key=key,value=value,condition=condition,terminal=terminal,result=result,severity="normal" if result == "success" else "warning")
                elif "type=NETFILTER_PKT" in line:
                    timestamp = self.extract_timestamp(line)
                    if not timestamp:
                        continue
                    second = 0 if timestamp.second < 30 else 30
                    timestamp_minute = timestamp.replace(second=second, microsecond=0)
                    src_ip_address = self.extract_match(r'saddr=([^\s]*)', line)
                    dst_ip_address = self.extract_match(r'daddr=([^\s]*)', line)
                    protocol_number = self.extract_match(r'proto=([^\s]*)', line)
                    match protocol_number:
                        case "1":
                            protocol = "ICMP"
                        case "6":
                            protocol = "TCP"
                        case "17":
                            protocol = "UDP"
                        case _:
                            protocol = f"not defined ({protocol_number})" if protocol_number else "not defined"
                    key = (timestamp_minute, src_ip_address, dst_ip_address, protocol)
                    packet_counts[key] += 1
        for (timestamp_minute, src_ip_address, dst_ip_address, protocol), count in packet_counts.items():
            NetfilterPackets.objects.create(timestamp=timestamp_minute,src_ip_address=src_ip_address,dst_ip_address=dst_ip_address,protocol=protocol,count=count)
    
    def extract_timestamp(self,line):
        match = re.search(r'msg=audit\((\d+\.\d+)', line)
        return timezone.make_aware(datetime.fromtimestamp(float(match.group(1)))) if match else None


    def extract_match(self,pattern, line, default=""):
        match = re.search(pattern, line)
        return match.group(1) if match else default


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
    entry_creator=CreateEntries()
    def test_single_clear_attack_detected(self):
        # create the specific entries from file logins_test.log
        self.entry_creator.make_entries('logins_test.log')
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

    def test_multiple_attack_mixed_w_logout(self):
        # create the specific entries
        UserLogin.objects.create(timestamp="2025-03-27 11:49:54.508+01", username="admin", src_ip_address="109.108.107.10", terminal="cdi8", result="success")
        UserLogin.objects.create(timestamp="2025-03-27 11:49:54.508+01", username="admin", src_ip_address="109.108.108.10", terminal="cdj8", result="success")
        UserLogin.objects.create(timestamp="2025-03-27 11:49:54.508+01", username="admin", src_ip_address="110.120.30.254", terminal="cdh9", result="success")
        UserLogin.objects.create(timestamp="2025-03-27 11:49:54.508+01", username="admin", src_ip_address="200.168.10.10", terminal="cdc8", result="success")
        UserLogout.objects.create(timestamp="2025-03-27 11:49:54.508+01", username="admin", terminal="cdc8")
        
        # test
        result=detect_concurrent_logins()
        self.assertEqual(result["concurrent_logins"],2)
        self.assertEqual(ConcurrentLoginIncident.objects.count(),2)
