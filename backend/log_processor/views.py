from django.conf import settings 
import os
from datetime import datetime
from django.shortcuts import render
from django.http import JsonResponse
from .models import User_Login

# Create your views here.
LOG_FILE_PATH = os.path.join(settings.BASE_DIR, '..', 'logs', 'brute_force_example.log')

def process_log(request):
    log_content = ""

    try:
        with open(LOG_FILE_PATH, 'r') as log_file:
            lines = log_file.readlines()
            entries_created = 0 # Counter for created entries

            for line in lines:
                if "type=USER_LOGIN" in line:    

                        # Split the line into parts based on whitespaces
                        parts = line.split()

                        timestamp = datetime.fromtimestamp(float(parts[1].replace("msg=audit(", "").split(":")[0])) #.strftime("%d.%m.%Y, %H:%M:%S")
                        username = parts[7].replace("acct=", "")
                        ipAddress = parts[10].replace("addr=", "")
                        result = parts[12].replace("res=", "")
                        
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
                #            
                #else if "OTHER_TYPE" in line:
                #    other log stuff
            return JsonResponse({"status": "success", "entries_created": entries_created})

    except FileNotFoundError:
        return JsonResponse({"status": "error", "message": "Log file not found."}, status=404)
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)
        