import re
import ipaddress
from datetime import datetime
from django.utils import timezone
import logging

def extract_timestamp(line):
    try:
        match = re.search(r'msg=audit\((\d+\.\d+)', line)
        if match:
            return timezone.make_aware(datetime.fromtimestamp(float(match.group(1))))
    except (ValueError, OverflowError) as e:
        logging.getLogger(__name__).warning(f"Invalid timestamp in log line: {str(e)}")
    return None

def extract_match(pattern, line, default=""):
    try:
        match = re.search(pattern, line)
        return match.group(1) if match else default
    except:
        return default

def is_valid_ip(ip_address):
    if not ip_address or ip_address == "?":
        return False
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def get_protocol_name(protocol_number):
    return {"1": "ICMP", "6": "TCP", "17": "UDP"}.get(protocol_number, f"Unknown ({protocol_number})" if protocol_number else "Unknown")
