import os
import re
import tempfile
import hashlib
from datetime import datetime
from django.utils import timezone
from collections import defaultdict
from log_processor.models import UploadedLogFile, UserLogin, UserLogout, UsysConfig, NetfilterPackets
from incident_detector.services import detect_incidents

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
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        hasher = hashlib.sha256()
        for chunk in uploaded_file.chunks():
            hasher.update(chunk)
            temp_file.write(chunk)
        file_hash = hasher.hexdigest()
        file_path = temp_file.name

    if UploadedLogFile.objects.filter(file_hash=file_hash).exists():
        os.unlink(file_path)
        return {"status": "duplicate", "file_hash": file_hash}

    try:
        result = process_log_file(file_path)
    except Exception:
        os.unlink(file_path)
        raise
    finally:
        if os.path.exists(file_path):
            os.unlink(file_path)

    uploaded_log_file = UploadedLogFile.objects.create(
        filename=uploaded_file.name,
        file_hash=file_hash,
        source=source,
        uploaded_by=uploaded_by_user,
        uploaded_at=timezone.now(),
        status='success' if result.get('status') != 'error' else 'error',
        entries_created=result.get('entries_created', 0),
        incidents_created_total=result.get('incidents_created_total', 0),
        incident_counts=result.get('incident_counts', {})
       
    )
    return {
    "status": result.get("status", "success"),
    "uploaded_log_file": uploaded_log_file,
    "entries_created": result.get("entries_created", 0),
    "incidents_created": result.get("incidents_created", 0)

} 



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
        with open(file_path, 'r') as log_file:
            for line in log_file:
                line = line.strip()

                # USER_LOGIN
                if "type=USER_LOGIN" in line:
                    timestamp = extract_timestamp(line)
                    if not timestamp:
                        continue

                    username = extract_match(r'acct="([^"]*)"', line)
                    src_ip_address = extract_match(r'addr=([^\s]*)', line)
                    result = extract_match(r'res=([^\'\s]*)', line)
                    terminal = extract_match(r'terminal=([^\s]*)', line)

                    if not UserLogin.objects.filter(
                        timestamp=timestamp,
                        username=username,
                        src_ip_address=src_ip_address,
                        result=result,
                        terminal=terminal
                    ).exists():
                        UserLogin.objects.create(
                            timestamp=timestamp,
                            username=username,
                            src_ip_address=src_ip_address,
                            result=result,
                            terminal=terminal,
                            severity="normal" if result == "success" else "warning"
                        )
                        entries_created += 1

                # USER_LOGOUT or USER_END
                elif "type=USER_LOGOUT" in line or "type=USER_END" in line:
                    timestamp = extract_timestamp(line)
                    if not timestamp:
                        continue

                    username = extract_match(r'acct="([^"]*)"', line)
                    result = extract_match(r'res=([^\'\s]*)', line)
                    terminal = extract_match(r'terminal=([^\s]*)', line)

                    if not UserLogout.objects.filter(
                        timestamp=timestamp,
                        username=username,
                        result=result,
                        terminal=terminal
                    ).exists():
                        UserLogout.objects.create(
                            timestamp=timestamp,
                            username=username,
                            result=result,
                            terminal=terminal,
                            severity="normal" if result == "success" else "warning"
                        )
                        entries_created += 1

                # USYS_CONFIG
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
                            table=table,
                            action=action,
                            key=key,
                            value=value,
                            condition=condition,
                            terminal=terminal,
                            result=result,
                            severity="normal" if result == "success" else "warning"
                        )
                        entries_created += 1

                # NETFILTER_PACKET
                elif "type=NETFILTER_PKT" in line:
                    timestamp = extract_timestamp(line)
                    if not timestamp:
                        continue
                    
                    # maybe tweak later (30s timeframe for packets)
                    second = 0 if timestamp.second < 30 else 30
                    timestamp_minute = timestamp.replace(second=second, microsecond=0)
                    
                    source_ip = extract_match(r'saddr=([^\s]*)', line)
                    destination_ip = extract_match(r'daddr=([^\s]*)', line)
                    protocol_number = extract_match(r'proto=([^\s]*)', line)

                    match protocol_number:
                        case "1":
                            protocol = "ICMP"
                        case "6":
                            protocol = "TCP"
                        case "17":
                            protocol = "UDP"
                        case _:
                            protocol = f"not defined ({protocol_number})" if protocol_number else "not defined"
                    
                    key = (timestamp_minute, source_ip, destination_ip, protocol)
                    packet_counts[key] += 1
        
        for (timestamp_minute, source_ip, destination_ip, protocol), count in packet_counts.items():
            NetfilterPackets.objects.create(
                timestamp=timestamp_minute,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                count=count
            )
            entries_created += 1  
                      
        result = detect_incidents()

        return {"status": "success","entries_created": entries_created,"incidents_created_total": len(result["incidents"]),"incident_counts": result["counts"]}

    except FileNotFoundError:
        return {
            "status": "error",
            "message": "Log file not found."
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
    
def extract_timestamp(line):
    """
    Helper function to extract the timestamp from a log line.
    Returns a timezone-aware datetime object.
    """
    match = re.search(r'msg=audit\((\d+\.\d+)', line)
    return timezone.make_aware(datetime.fromtimestamp(float(match.group(1)))) if match else None


def extract_match(pattern, line, default=""):
    """
    Helper function to extract a regex match group from a line.
    Returns the matched group or the default value if no match is found.
    """
    match = re.search(pattern, line)
    return match.group(1) if match else default






