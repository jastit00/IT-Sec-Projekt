import os
import re
from datetime import datetime
from django.utils import timezone
from incident_detector.services import detect_incidents
from .models import User_Login, Usys_Config, User_Logout, NetfilterPkt

def process_log_file(file_path: str) -> dict:
    entries_created = 0
    try:
        with open(file_path, 'r') as log_file:
            lines = log_file.readlines()
            for line in lines:        
                
                # check for USER_LOGIN        
                if "type=USER_LOGIN" in line:
                    # get timestampm and convert it to datetime object
                    timestamp = timezone.make_aware(datetime.fromtimestamp(float(re.search(r'msg=audit\((\d+\.\d+)', line).group(1))))

                    # Extract other fields using regex
                    username_match = re.search(r'acct="([^"]*)"', line)
                    ip_address_match = re.search(r'addr=([^\s]*)', line)
                    result_match = re.search(r"res=([^'\s]*)", line)
                    terminal_match = re.search(r'terminal=([^\s]*)', line)

                    # set default values if regex fails
                    username = username_match.group(1) if username_match else ""
                    ip_address = ip_address_match.group(1) if ip_address_match else ""
                    result = result_match.group(1) if result_match else ""
                    terminal = terminal_match.group(1) if terminal_match else ""

                    # check if th DB-object already exists and create it if not
                    if not User_Login.objects.filter(
                        timestamp=timestamp, 
                        username=username, 
                        ip_address=ip_address,
                        result=result,
                        terminal=terminal
                        ).exists():
                        User_Login.objects.create(
                            log_type="USER_LOGIN",
                            timestamp=timestamp,
                            username=username,
                            ip_address=ip_address,
                            result=result,
                            terminal=terminal
                        )
                        entries_created += 1 # increment counter for each new entry

                 # check for USER_LOGOUT or timeout      
                elif "type=USER_LOGOUT" in line or "type=USER_END" in line:
                    # get timestampm and convert it to datetime object
                    timestamp = timezone.make_aware(datetime.fromtimestamp(float(re.search(r'msg=audit\((\d+\.\d+)', line).group(1))))

                    # Extract other fields using regex
                    username_match = re.search(r'acct="([^"]*)"', line)
                    result_match = re.search(r"res=([^'\s]*)", line)
                    terminal_match = re.search(r'terminal=([^\s]*)', line)

                    # set default values if regex fails
                    username = username_match.group(1) if username_match else ""
                    result = result_match.group(1) if result_match else ""
                    terminal = terminal_match.group(1) if terminal_match else ""

                    # check if th DB-object already exists and create it if not
                    if not User_Logout.objects.filter(
                        timestamp=timestamp, 
                        username=username, 
                        result=result,
                        terminal=terminal
                        ).exists():
                        User_Logout.objects.create(
                            log_type="USER_LOGOUT",
                            timestamp=timestamp,
                            username=username,
                            result=result,
                            terminal=terminal
                        )
                        entries_created += 1 # increment counter for each new entry
                
                # check for USYS_CONFIG
                elif "type=USYS_CONFIG" in line:
                    # Extract timestamp
                    timestamp = timezone.make_aware(datetime.fromtimestamp(float(re.search(r'msg=audit\((\d+\.\d+)', line).group(1))))

                    # this needs to be tweaked maybe
                    table_match = re.search(r'table="([^"]*)"', line)  
                    action_match = re.search(r'action="([^"]*)"', line)  
                    key_match = re.search(r'key="([^"]*)"', line)  
                    value_match = re.search(r'value="([^"]*)"?', line)  
                    condition_match = re.search(r'condition="([^"]*)"', line)  
                    terminal_match = re.search(r'terminal\s*=\s*([^\s]*)', line)  
                    result_match = re.search(r"res\s*=\s*([^'\s]*)", line) 
                    

                    # set default values if regex fails
                    action = action_match.group(1) if action_match else ""
                    key = key_match.group(1) if key_match else ""
                    value = value_match.group(1) if value_match else ""
                    condition = condition_match.group(1) if condition_match else ""
                    table = table_match.group(1) if table_match else ""
                    terminal = terminal_match.group(1) if terminal_match else ""
                    result = result_match.group(1) if result_match else ""         

                    if not Usys_Config.objects.filter(
                        timestamp=timestamp,
                        table=table,
                        action=action,
                        key=key,
                        value=value,
                        condition=condition,
                        terminal=terminal,
                        result=result,
                    ).exists():
                        Usys_Config.objects.create(
                            log_type="USYS_CONFIG",
                            timestamp=timestamp,
                            table=table,
                            action=action,
                            key=key,
                            value=value,
                            condition=condition,
                            terminal=terminal,
                            result=result,
                        )
                        entries_created += 1
                
                # check for NETFILTER_PACKET
                elif "type=NETFILTER_PKT" in line:
                    # Extract timestamp
                    timestamp = timezone.make_aware(datetime.fromtimestamp(float(re.search(r'msg=audit\((\d+\.\d+)', line).group(1))))

                    # Extract other fields using regex
                    source_ip_match = re.search(r'saddr=([^\s]*)', line)
                    destination_ip_match = re.search(r'daddr=([^\s]*)', line)
                    protocol_match = re.search(r'proto=([^\s]*)', line)

                    # set default values if regex fails
                    source_ip = source_ip_match.group(1) if source_ip_match else ""
                    destination_ip = destination_ip_match.group(1) if destination_ip_match else ""
                    protocol_number = protocol_match.group(1) if protocol_match else ""

                    match protocol_number:
                        case "1":
                            protocol = "ICMP"
                        case "6":
                             protocol = "TCP"
                        case "17":
                             protocol = "UDP"
                        case _: 
                            protocol = "not defined ({protocol_number})" if protocol_number else "not defined"
                    
                    # check if th DB-object already exists and create it if not
                    if not NetfilterPkt.objects.filter(
                        timestamp=timestamp,
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        protocol=protocol,
                    ).exists():
                        NetfilterPkt.objects.create(
                            log_type="NETFILTER_PKT",
                            timestamp=timestamp,
                            source_ip=source_ip,
                            destination_ip=destination_ip,
                            protocol=protocol,
                        )
                        entries_created += 1


        incidents_created = detect_incidents()
        return {
            "status": "success",
            "entries_created": entries_created,
            "incidents_created": incidents_created,
        }

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