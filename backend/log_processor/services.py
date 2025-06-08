import os
import re
import tempfile
import hashlib
import ipaddress

from datetime import datetime
from collections import defaultdict
from django.utils import timezone

from log_processor.models import (
    UploadedLogFile, 
    UserLogin,
    UserLogout,
    UsysConfig,
    NetfilterPackets,
)

from incident_detector.services.detection import detect_incidents


def handle_uploaded_log_file(uploaded_file, source, uploaded_by_user):
    """
    Handles a newly uploaded log file by saving it temporarily, calculating its SHA-256 hash,
    checking for duplicates, processing its contents, and storing metadata in the database.
    
    Parameters: 
        uploaded_file (InMemoryUploadedFile): The uploaded log file.
        source (str): The source of the upload.
        uploaded_by_user (str): The user who uploaded the file.
    
    Returns:
        dict: A dictionary containing the status of the upload and any relevant metadata.
    """
    temp_file_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            hasher = hashlib.sha256()
            for chunk in uploaded_file.chunks():
                hasher.update(chunk)
                temp_file.write(chunk)
            file_hash = hasher.hexdigest()
            temp_file_path = temp_file.name

        
        if UploadedLogFile.objects.filter(file_hash=file_hash).exists():
            return {"status": "duplicate", "file_hash": file_hash}

        
        try:
            result = process_log_file(temp_file_path)
        except Exception:
           
            result = {"status": "error", "entries_created": 0, "incidents_created_total": 0, "incident_counts": {}}
        
      
        uploaded_log_file = UploadedLogFile.objects.create(
            filename=uploaded_file.name,
            file_hash=file_hash,
            source=source,
            uploaded_by=uploaded_by_user,
            uploaded_at=timezone.now(),
            status='success' if result.get('status') == 'success' else 'error',
            entries_created=result.get('entries_created', 0),
            incidents_created_total=result.get('incidents_created_total', 0),
            incident_counts=result.get('incident_counts', {})
        )
        
        return {
            "status": "success",  
            "uploaded_log_file": uploaded_log_file,
            "entries_created": result.get("entries_created", 0),
            "incidents_created_total": result.get("incidents_created_total", 0)
        }
        
    except Exception:
        
        try:
            uploaded_log_file = UploadedLogFile.objects.create(
                filename=uploaded_file.name,
                file_hash="error",
                source=source,
                uploaded_by=uploaded_by_user,
                uploaded_at=timezone.now(),
                status='error',
                entries_created=0,
                incidents_created_total=0,
                incident_counts={}
            )
            return {
                "status": "success",
                "uploaded_log_file": uploaded_log_file,
                "entries_created": 0,
                "incidents_created_total": 0
            }
        except:
      
            return {
                "status": "success", 
                "entries_created": 0,
                "incidents_created_total": 0
            }
    finally:
       
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.unlink(temp_file_path)
            except:
                pass


def process_log_file(file_path):
    """
    Parses an audit log file, extracts entries, saves them to the database,
    and triggers incident detection.

    Parameters:
        file_path: Path to the temporary uploaded log file.

    Returns:
        dict: A dictionary containing the status of the processing and the number of entries created.
    """
    entries_created = 0
    packet_counts = defaultdict(int)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as log_file:
            for line in log_file:
                try:
                    line = line.strip()
                    if not line:
                        continue

                    if "type=USER_LOGIN" in line:
                        timestamp = extract_timestamp(line)
                        if not timestamp:
                            continue

                        username = extract_match(r'acct="([^"]*)"', line)
                        src_ip_address = extract_match(r'addr=([^\s]*)', line)
                        result = extract_match(r'res=([^\'\s]*)', line)
                        terminal = extract_match(r'terminal=([^\s]*)', line)

                        # Skip invalid IP addresses
                        if src_ip_address and not is_valid_ip(src_ip_address):
                            src_ip_address = None

                        try:
                            if not UserLogin.objects.filter(
                                timestamp=timestamp,
                                username=username,
                                src_ip_address=src_ip_address,
                                result=result,
                                terminal=terminal
                            ).exists():
                                UserLogin.objects.create(
                                    timestamp=timestamp,
                                    username=username or "",
                                    src_ip_address=src_ip_address,
                                    result=result or "",
                                    terminal=terminal,
                                    severity="normal" if result == "success" else "warning"
                                )
                                entries_created += 1
                        except:
                            continue

                    elif "type=USER_LOGOUT" in line or "type=USER_END" in line:
                        timestamp = extract_timestamp(line)
                        if not timestamp:
                            continue

                        username = extract_match(r'acct="([^"]*)"', line)
                        result = extract_match(r'res=([^\'\s]*)', line)
                        terminal = extract_match(r'terminal=([^\s]*)', line)

                        try:
                            if not UserLogout.objects.filter(
                                timestamp=timestamp,
                                username=username,
                                result=result,
                                terminal=terminal
                            ).exists():
                                UserLogout.objects.create(
                                    timestamp=timestamp,
                                    username=username or "",
                                    result=result or "",
                                    terminal=terminal,
                                    severity="normal" if result == "success" else "warning"
                                )
                                entries_created += 1
                        except:
                            continue

                    elif "type=USYS_CONFIG" in line:
                        timestamp = extract_timestamp(line)
                        if not timestamp:
                            continue

                        table = extract_match(r'table="([^"]*)"', line)
                        action = extract_match(r'action="([^"]*)"', line)
                        key = extract_match(r'key="([^"]*)"', line)
                        value = extract_match(r'value="([^"]*)"?', line)
                        condition = extract_match(r'condition="([^"]*)"', line)
                        terminal = extract_match(r'terminal\s*=\s*([^\s]*)', line)
                        result = extract_match(r'res\s*=\s*([^\'\s]*)', line)

                        try:
                            if not UsysConfig.objects.filter(
                                timestamp=timestamp,
                                table=table,
                                action=action,
                                key=key,
                                value=value,
                                condition=condition,
                                terminal=terminal,
                                result=result
                            ).exists():
                                UsysConfig.objects.create(
                                    timestamp=timestamp,
                                    table=table or "",
                                    action=action or "",
                                    key=key,
                                    value=value,
                                    condition=condition,
                                    terminal=terminal or "",
                                    result=result or "",
                                    severity="normal" if result == "success" else "warning"
                                )
                                entries_created += 1
                        except:
                            continue

                    elif "type=NETFILTER_PKT" in line:
                        timestamp = extract_timestamp(line)
                        if not timestamp:
                            continue
                        
                        second = 0 if timestamp.second < 30 else 30
                        rounded_timestamp = timestamp.replace(second=second, microsecond=0)
                           
                         # 30s timeframe for packets
                        src_ip_address = extract_match(r'saddr=([^\s]*)', line)
                        dst_ip_address = extract_match(r'daddr=([^\s]*)', line)
                        protocol_number = extract_match(r'proto=([^\s]*)', line)

                        if is_valid_ip(src_ip_address) and is_valid_ip(dst_ip_address):
                            protocol = get_protocol_name(protocol_number)
                            key = (rounded_timestamp, src_ip_address, dst_ip_address, protocol)
                            packet_counts[key] += 1
                        
                except:
                    continue
        
    
        for (rounded_timestamp, src_ip_address, dst_ip_address, protocol), count in packet_counts.items():
            try:
                NetfilterPackets.objects.create(
                    timestamp=rounded_timestamp,
                    src_ip_address=src_ip_address,
                    dst_ip_address=dst_ip_address,
                    protocol=protocol,
                    count=count
                )
                entries_created += 1
            except:
                continue
                      
  
        try:
            result = detect_incidents()
            incidents_created_total = len(result.get("incidents", []))
            incident_counts = result.get("counts", {})
        except:
            incidents_created_total = 0
            incident_counts = {}

        return {
            "status": "success",
            "entries_created": entries_created,
            "incidents_created_total": incidents_created_total,
            "incident_counts": incident_counts
        }

    except:
    
        return {
            "status": "success",
            "entries_created": 0,
            "incidents_created_total": 0,
            "incident_counts": {}
        }


def extract_timestamp(line):
    """
    Helper function to extract the timestamp from a log line.
    Returns a timezone-aware datetime object.
    """
    try:
        match = re.search(r'msg=audit\((\d+\.\d+)', line)
        if match:
            timestamp_float = float(match.group(1))
            return timezone.make_aware(datetime.fromtimestamp(timestamp_float))
    except (ValueError, OverflowError) as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Invalid timestamp in log line: {str(e)}")
    return None


def extract_match(pattern, line, default=""):
    """
    Helper function to extract a regex match group from a line.
    Returns the matched group or the default value if no match is found.
    """
    try:
        match = re.search(pattern, line)
        return match.group(1) if match else default
    except Exception:
        return default


def is_valid_ip(ip_address):
    """
    Validate if the given string is a valid IP address.
    """
    if not ip_address or ip_address == "?":
        return False
    
  
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def get_protocol_name(protocol_number):
    """
    Convert protocol number to protocol name.
    """
    protocol_map = {
        "1": "ICMP",
        "6": "TCP", 
        "17": "UDP"
    }
    return protocol_map.get(protocol_number, f"Unknown ({protocol_number})" if protocol_number else "Unknown")