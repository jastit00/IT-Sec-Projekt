from django.conf import settings 
import os
from datetime import datetime
from django.shortcuts import render
from django.http import JsonResponse
from .models import User_Login
from incident_detector.services import detect_incidents

# Create your views here.

# this is the log path change it later to get the log file from frontend
LOG_FILE_PATH = os.path.join(settings.BASE_DIR, '..', 'logs', 'brute_force_example.log')

def process_log(request):
    try:
        with open(LOG_FILE_PATH, 'r') as log_file:
            lines = log_file.readlines()
            entries_created = 0 # Counter for created entries

            for line in lines:
                if "type=USER_LOGIN" in line:    

                    # Split the line into parts based on whitespaces
                    parts = line.split()

                    # extract relevant data (no srftime because DB field is DateTimeField)
                    timestamp = datetime.fromtimestamp(float(parts[1].replace("msg=audit(", "").split(":")[0])) #.strftime("%d.%m.%Y, %H:%M:%S")
                    username = parts[7].replace("acct=", "").strip('"')
                    ipAddress = parts[10].replace("addr=", "")
                    result = parts[12].replace("res=", "").strip("'")
                        
                    # Create database entry here
                    if not User_Login.objects.filter(timestamp=timestamp, username=username, ipAddress=ipAddress, result=result).exists():
                        User_Login.objects.create(
                            log_type="USER_LOGIN",
                            timestamp=timestamp,
                            username=username,
                            ipAddress=ipAddress,
                            result=result
                        )
                        entries_created += 1
                
                # Placeholder            
                #else if "OTHER_TYPE" in line:
                #    other log stuff
                #    ....
            
            
            incidents_created = detect_incidents()

            # Return a JsonResponse with status, number of entries created, and debug info
            return JsonResponse({
                "status": "success",
                "entries_created": entries_created,
                "incidents_created": incidents_created  
            })
    
    # error if log file not found
    except FileNotFoundError:
        return JsonResponse({"status": "error", "message": "Log file not found."}, status=404)
    # error if other stuff goes wrong
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)
        
