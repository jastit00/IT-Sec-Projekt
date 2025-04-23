import os
from datetime import datetime
from django.utils import timezone
from incident_detector.services import detect_incidents
from incident_detector.models import User_Login

def process_log_file(file_path: str) -> dict:
    entries_created = 0

    try:
        with open(file_path, 'r') as log_file:
            lines = log_file.readlines()

            for line in lines:
                if "type=USER_LOGIN" in line:
                    parts = line.split()
                    try:
                        naive_timestamp = datetime.fromtimestamp(float(parts[1].replace("msg=audit(", "").split(":")[0]))
                        timestamp = timezone.make_aware(naive_timestamp)
                        username = parts[7].replace("acct=", "").strip('"')
                        ipAddress = parts[10].replace("addr=", "")
                        result = parts[12].replace("res=", "").strip("'")

                        if not User_Login.objects.filter(timestamp=timestamp, username=username, ipAddress=ipAddress, result=result).exists():
                            User_Login.objects.create(
                                log_type="USER_LOGIN",
                                timestamp=timestamp,
                                username=username,
                                ipAddress=ipAddress,
                                result=result
                            )
                            entries_created += 1
                    except Exception as parse_err:
                        continue  # Skip malformed lines or log them later

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