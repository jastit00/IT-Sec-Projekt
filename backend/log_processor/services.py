import os
import re
from datetime import datetime
from django.utils import timezone
from incident_detector.services import detect_incidents
from .models import User_Login, Usys_Config

def process_log_file(file_path: str) -> dict:
    entries_created = 0


    try:
        with open(file_path, 'r') as log_file:
            lines = log_file.readlines()
            for line in lines:        
               
                
                # check for USER_LOGIN        
                if "type=USER_LOGIN" in line:
                    # get timestamp
                    timestamp = timezone.make_aware(datetime.fromtimestamp(float(re.search(r'msg=audit\((\d+\.\d+)', line).group(1))))

                    # Extract other fields using regex
                    username_match = re.search(r'acct="([^"]*)"', line)
                    ip_match = re.search(r'addr=([^\s]*)', line)
                    result_match = re.search(r"res=([^'\s]*)", line)

                    # set default values if regex fails
                    username = username_match.group(1) if username_match else ""
                    ipAddress = ip_match.group(1) if ip_match else ""
                    result = result_match.group(1) if result_match else ""

                    # check if th DB-object already exists and create it if not
                    if not User_Login.objects.filter(timestamp=timestamp, username=username, ipAddress=ipAddress, result=result).exists():
                        User_Login.objects.create(
                            log_type="USER_LOGIN",
                            timestamp=timestamp,
                            username=username,
                            ipAddress=ipAddress,
                            result=result
                        )
                        entries_created += 1 # increment counter for each new entry


                elif "type=USYS_CONFIG" in line:
                    # Extract timestamp
                    timestamp = timezone.make_aware(datetime.fromtimestamp(float(re.search(r'msg=audit\((\d+\.\d+)', line).group(1))))


                    # this needs to be tweaked maybe
                    message_match = re.search(r'table="([^"]+)"', line) 
                    action_match = re.search(r'action="([^"]*)"', line)
                    key_match = re.search(r'key="([^"]*)"', line)
                    value_match = re.search(r'value="([^"]*)"', line)
                    condition_match = re.search(r'condition="([^"]*)"', line)
                    terminal_match = re.search(r'terminal=([^\s]*)', line)
                    result_match = re.search(r"res=([^'\s]*)", line)

                    action = action_match.group(1) if action_match else ""
                    key = key_match.group(1) if key_match else ""
                    value = value_match.group(1) if value_match else ""
                    condition = condition_match.group(1) if condition_match else ""
                    message = message_match.group(1) if message_match else ""
                    terminal = terminal_match.group(1).strip("'") if terminal_match else ""
                    result = result_match.group(1) if result_match else ""

                    if not Usys_Config.objects.filter(
                        timestamp=timestamp,
                        message=message,
                        action=action,
                        key=key,
                        value=value,
                        condition=condition,
                        terminal=terminal,
                        result=result
                    ).exists():
                        Usys_Config.objects.create(
                            log_type="USYS_CONFIG",
                            timestamp=timestamp,
                            message=message,
                            action=action,
                            key=key,
                            value=value,
                            condition=condition,
                            terminal=terminal,
                            result=result
                        )
                        entries_created += 1

        incidents_created = detect_incidents()
        return {
            "status": "success",
            "entries_created": entries_created,
            "incidents_created": incidents_created
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