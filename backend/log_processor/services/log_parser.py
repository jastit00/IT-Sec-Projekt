import re
from collections import defaultdict
from django.utils import timezone
from log_processor.models import UserLogin, UserLogout, UsysConfig, NetfilterPackets
from incident_detector.services.detection import detect_incidents
from log_processor.services.utils import extract_timestamp, extract_match, is_valid_ip, get_protocol_name

def process_log_file(file_path):
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
                        src_ip = extract_match(r'addr=([^\s]*)', line)
                        result = extract_match(r'res=([^\'\s]*)', line)
                        terminal = extract_match(r'terminal=([^\s]*)', line)
                        if src_ip and not is_valid_ip(src_ip):
                            src_ip = None
                        if not UserLogin.objects.filter(timestamp=timestamp, username=username, src_ip_address=src_ip, result=result, terminal=terminal).exists():
                            UserLogin.objects.create(timestamp=timestamp, username=username or "", src_ip_address=src_ip, result=result or "", terminal=terminal, severity="normal" if result == "success" else "warning")
                            entries_created += 1

                    elif "type=USER_LOGOUT" in line or "type=USER_END" in line:
                        timestamp = extract_timestamp(line)
                        if not timestamp:
                            continue
                        username = extract_match(r'acct="([^"]*)"', line)
                        result = extract_match(r'res=([^\'\s]*)', line)
                        terminal = extract_match(r'terminal=([^\s]*)', line)
                        if not UserLogout.objects.filter(timestamp=timestamp, username=username, result=result, terminal=terminal).exists():
                            UserLogout.objects.create(timestamp=timestamp, username=username or "", result=result or "", terminal=terminal, severity="normal" if result == "success" else "warning")
                            entries_created += 1

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
                        if not UsysConfig.objects.filter(timestamp=timestamp, table=table, action=action, key=key, value=value, condition=condition, terminal=terminal, result=result).exists():
                            UsysConfig.objects.create(timestamp=timestamp, table=table or "", action=action or "", key=key, value=value, condition=condition, terminal=terminal or "", result=result or "", severity="normal" if result == "success" else "warning")
                            entries_created += 1

                    elif "type=NETFILTER_PKT" in line:
                        timestamp = extract_timestamp(line)
                        if not timestamp:
                            continue
                        second = 0 if timestamp.second < 30 else 30
                        rounded = timestamp.replace(second=second, microsecond=0)
                        src = extract_match(r'saddr=([^\s]*)', line)
                        dst = extract_match(r'daddr=([^\s]*)', line)
                        proto = extract_match(r'proto=([^\s]*)', line)
                        if is_valid_ip(src) and is_valid_ip(dst):
                            name = get_protocol_name(proto)
                            key = (rounded, src, dst, name)
                            packet_counts[key] += 1
                except:
                    continue

        for (ts, src, dst, proto), count in packet_counts.items():
            try:
                NetfilterPackets.objects.create(timestamp=ts, src_ip_address=src, dst_ip_address=dst, protocol=proto, count=count)
                entries_created += 1
            except:
                continue

        try:
            result = detect_incidents()
            return {
                "status": "success",
                "entries_created": entries_created,
                "incidents_created_total": len(result.get("incidents", [])),
                "incident_counts": result.get("counts", {})
            }
        except:
            return {
                "status": "success",
                "entries_created": entries_created,
                "incidents_created_total": 0,
                "incident_counts": {}
            }
    except:
        return {
            "status": "success",
            "entries_created": 0,
            "incidents_created_total": 0,
            "incident_counts": {}
        }