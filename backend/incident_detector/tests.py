from django.test import TestCase
from django.utils import timezone
from log_processor.models import UserLogin, UserLogout, UsysConfig, NetfilterPackets
from .models import BruteforceIncident, ConcurrentLoginIncident, ConfigIncident, DosIncident, DDosIncident
from .services import detect_bruteforce, detect_incidents, detect_concurrent_logins, detect_critical_config_change, detect_dos_attack, detect_ddos_attack
from datetime import timedelta

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
    entry_creator=CreateEntries()
    def test_no_bruteforce_if_too_few_attempts(self):
        # create the specific entries from file not_enough_tries.log
        self.entry_creator.make_entries('not_enough_tries.log')
        # test
        result = detect_bruteforce()
        self.assertEqual(result["bruteforce"], 0)
        self.assertEqual(BruteforceIncident.objects.count(), 0)
        self.assertEqual(UserLogin.objects.count(), 4)
        
    def test_detect_bruteforce_attempt(self):
        # create the specific entries from file clear_simple_bruteforce.log
        self.entry_creator.make_entries('clear_simple_bruteforce.log')
        # test
        result = detect_bruteforce()
        self.assertEqual(result["bruteforce"], 1)
        self.assertEqual(BruteforceIncident.objects.count(), 1)

    def test_spaced_attemps_still_detected(self):
        # create the specific entries from file spaced_tries.log
        self.entry_creator.make_entries('spaced_tries.log')
        # test
        result = detect_bruteforce()
        self.assertEqual(result["bruteforce"], 1)
        self.assertEqual(UserLogin.objects.count(),17)

    def test_successful_last_attempt_changes_reason(self):
        # create the specific entries from file successful_bruteforce.log
        self.entry_creator.make_entries('successful_bruteforce.log')
        # test
        result=detect_bruteforce()
        incident = BruteforceIncident.objects.first()
        self.assertIn("20 attempts in 2 minutes, 1 successful", incident.reason)
        self.assertEqual(result["bruteforce"],1)

    def test_detect_incidents_wrapper(self):
        # create the specific entries from file several_clear_bruteforce.log
        self.entry_creator.make_entries('several_clear_bruteforce.log')
        # test
        result = detect_incidents()
        self.assertEqual(result["counts"]["bruteforce"], 2)
    
    def test_duplicate_incident_is_not_created(self):
        self.entry_creator.make_entries('clear_simple_bruteforce.log')
        detect_bruteforce()
        detect_bruteforce()  # call twice
        self.assertEqual(BruteforceIncident.objects.count(), 1)

    def test_detect_attack_by_different_ip(self):
        # create the specific entries from file several_ip_bruteforce.log
        self.entry_creator.make_entries("several_ip_bruteforce.log")
        # test
        result=detect_incidents()
        self.assertEqual(result["counts"]["brute_force"],1)
       
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
        # create the specific entries from file many_simultaneous_logins.log
        self.entry_creator.make_entries('many_simultaneous_logins.log')
        # test
        result=detect_concurrent_logins()
        self.assertEqual(result["concurrent_logins"],3)
        self.assertEqual(ConcurrentLoginIncident.objects.count(),3)

    def test_multiple_attack_mixed_w_logout(self):
        # create the specific entries from file mix_logins.log
        self.entry_creator.make_entries('mix_logins.log')
        # test
        result=detect_concurrent_logins()
        self.assertEqual(result["concurrent_logins"],2)
        self.assertEqual(ConcurrentLoginIncident.objects.count(),2)

    def test_no_attack_single_pair_login_logout(self):
        # create the specific entries from file valid_login.log
        self.entry_creator.make_entries('valid_login.log')
        # test
        result=detect_concurrent_logins()
        self.assertEqual(result["concurrent_logins"],0)
        self.assertEqual(UserLogin.objects.count(),1)
        self.assertEqual(UserLogout.objects.count(),1)

    def test_no_attack_several_pairs_login_logout(self):
        # create the specific entries from file many_valid_logins.log
        self.entry_creator.make_entries('many_valid_logins.log')
        # test
        result=detect_concurrent_logins()
        self.assertEqual(result["concurrent_logins"],0)
        self.assertEqual(UserLogin.objects.count(),3)
        self.assertEqual(UserLogout.objects.count(),3)

    def test_several_attacks_several_pairs_login_logout(self):
        # create the specific entries from file many_mix_logins.log
        self.entry_creator.make_entries('many_mix_logins.log')
        # test
        result=detect_concurrent_logins()
        self.assertEqual(result["concurrent_logins"],3)
        self.assertEqual(UserLogin.objects.count(),9)
        self.assertEqual(UserLogout.objects.count(),3)

class ConfigChangeDetectionTest(TestCase):
    entry_creator=CreateEntries()
    def test_single_critical_change_w_previous_user_login(self):
        # create the specific entries from file config_change_user_login.log
        self.entry_creator.make_entries('config_change_user_login.log')
        # test
        result=detect_critical_config_change()
        self.assertEqual(result["critical_config_change"],1)
        self.assertEqual(ConfigIncident.objects.first().src_ip_address,UserLogin.objects.first().src_ip_address)

    def test_multiple_config_change_from_single_user(self):
        # create the specific entries from file many_config_changes_single_login.log
        self.entry_creator.make_entries('many_config_changes_single_login.log')
        # test
        result=detect_critical_config_change()
        self.assertEqual(result["critical_config_change"],5)
        self.assertEqual(UsysConfig.objects.count(),7)
        for incident in ConfigIncident.objects.all():
            self.assertEqual(incident.src_ip_address,UserLogin.objects.first().src_ip_address)
    def test_single_critical_change_no_previous_login(self):
        # create the specific entries from file config_change_alone.log
        self.entry_creator.make_entries('config_change_alone.log')
        # test
        result=detect_critical_config_change()
        self.assertEqual(result["critical_config_change"],1)
        self.assertEqual(ConfigIncident.objects.first().src_ip_address, None)

    def test_multiple_config_change_from_single_user(self):
        # create the specific entries from file many_config_changes_single_login.log
        self.entry_creator.make_entries('many_config_changes_single_login.log')
        # test
        result=detect_critical_config_change()
        self.assertEqual(result["critical_config_change"],5)
        self.assertEqual(UsysConfig.objects.count(),7)
        for incident in ConfigIncident.objects.all():
            self.assertEqual(incident.src_ip_address,UserLogin.objects.first().src_ip_address)
            
    def test_multiple_config_changes_from_several_users(self):
        # create the specific entries from file many_config_changes_many_users.log
        self.entry_creator.make_entries('many_config_changes_many_users.log')
        # test
        result=detect_critical_config_change()
        self.assertEqual(result["critical_config_change"],9)
        self.assertEqual(ConfigIncident.objects.filter(username='testuser').count(),5)
        self.assertEqual(ConfigIncident.objects.filter(username='badguy').count(),2)
        self.assertEqual(ConfigIncident.objects.filter(username='anotherone').count(),2)

    def test_multiple_config_change_with_later_login(self):
        # create the specific entries from many_config_changes_no_proper_login.log
        self.entry_creator.make_entries('many_config_changes_late_login.log')
        # test
        result=detect_critical_config_change()
        self.assertEqual(result["critical_config_change"],6)
        for incident in ConfigIncident.objects.filter(username='testuser'):
            self.assertEqual(incident.src_ip_address, None)

    def test_multiple_config_change_with_invalid_login(self):
        # create the specific entries from many_config_changes_no_valid_login.log
        self.entry_creator.make_entries('many_config_changes_no_valid_login.log')
        # test
        result=detect_critical_config_change()
        self.assertEqual(result["critical_config_change"],6)
        self.assertEqual(UserLogin.objects.first().result,'failed')
        for incident in ConfigIncident.objects.all():
            self.assertEqual(incident.src_ip_address, None)
            
    def test_almost_critical_config_change(self):
        # create the specific entries from almost_critical_config_change.log
        self.entry_creator.make_entries('almost_critical_config_change.log')
        # test
        result=detect_critical_config_change()
        self.assertEqual(result["critical_config_change"],0)
        self.assertEqual(UsysConfig.objects.count(),6)

    def test_change_of_severity(self):
        # create the specific entries from many_config_changes_mix_severity.log
        self.entry_creator.make_entries('many_config_changes_mix_severity.log')
        # test
        result=detect_critical_config_change()
        self.assertEqual(result["critical_config_change"],4)
        self.assertEqual(ConfigIncident.objects.all()[0].severity,'critical')
        self.assertEqual(ConfigIncident.objects.all()[1].severity,'high')

    def test_multiple_config_changes_from_different_users_mix_valid_logins(self):
        # create the specific entries from many_config_changes_mix_logins.log
        self.entry_creator.make_entries('many_config_changes_mix_logins.log')
        # test
        result=detect_critical_config_change()
        self.assertEqual(result["critical_config_change"],6)
        self.assertEqual(result["incidents"][0].src_ip_address,None)
        self.assertEqual(result["incidents"][2].src_ip_address,UserLogin.objects.order_by('timestamp').first().src_ip_address)

    def test_no_critical_changes_performed(self):
        # create the specific entries from file valid_config_changes.log
        self.entry_creator.make_entries('valid_config_changes.log')
        # test
        result=detect_critical_config_change()
        self.assertEqual(result["critical_config_change"],0)
        self.assertEqual(UserLogin.objects.count(),0)
        self.assertEqual(UsysConfig.objects.count(), 53)

class DoSDetectionTest(TestCase):
    entry_creator=CreateEntries()
    def test_single_clear_dos_attack_detected(self):
        # create the specific entries from file single_clear_dos_attack.log
        self.entry_creator.make_entries('single_clear_dos_attack.log')
        # test
        result=detect_dos_attack()
        self.assertEqual(result["dos_attacks"],1)
        self.assertEqual(NetfilterPackets.objects.count(),1)
        self.assertEqual(DosIncident.objects.first().src_ip_address,'172.16.0.2')

    def test_unrecognized_attack_spaced_in_30s(self):
        # creating the specific entries from file extenden_dos_attack_spaced.log
        self.entry_creator.make_entries('extenden_dos_attack_spaced.log')
        # test
        result=detect_dos_attack()
        self.assertEqual(result["dos_attacks"],0)
        self.assertEqual(NetfilterPackets.objects.count(),144)

    def test_not_enogh_packets_to_recognice_attack(self):
        # creating the specific entries from file dos_attack_not_enough_packets.log
        self.entry_creator.make_entries('dos_attack_not_enough_packets.log')
        # test
        result=detect_dos_attack()
        self.assertEqual(result["dos_attacks"],0)
        self.assertEqual(NetfilterPackets.objects.count(),1)

    def test_multiples_dos_attacks_from_same_ip(self):
        # creating the specific entries from file double_dos_attack_same_ip.log
        self.entry_creator.make_entries('double_dos_attack_same_ip.log')
        # test
        result=detect_dos_attack()
        self.assertEqual(result["dos_attacks"],2)
        self.assertEqual(DosIncident.objects.all()[0].dst_ip_address,'192.168.0.88')
        self.assertEqual(DosIncident.objects.all()[1].dst_ip_address,'192.124.0.59')

    def test_very_long_dos_attack_two_incidents_generated(self):
        # creating the specific entries from file very_long_dos_attack.log
        self.entry_creator.make_entries('very_long_dos_attack.log')
        # test
        result=detect_dos_attack()
        self.assertEqual(result["dos_attacks"],2)
        self.assertEqual(NetfilterPackets.objects.count(),8)
        # from first entry till lats enry there is approx. 3 minutes and 42 seconds-> 3min = 6*30sec; 42 = 30sec+rest
