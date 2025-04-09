from django.conf import settings 
import os
from datetime import datetime
from django.shortcuts import render
from django.http import HttpResponse
from .models import User_Login

# Create your views here.
LOG_FILE_PATH = os.path.join(settings.BASE_DIR, '..', 'logs', 'brute_force_example.log')

def process_log(request):
    log_content = ""

    try:
        with open(LOG_FILE_PATH, 'r') as log_file:
            lines = log_file.readlines()
            for line in lines:
                if "type=USER_LOGIN" in line:    

                        # Split the line into parts based on whitespaces
                        parts = line.split()

                        timestamp = datetime.fromtimestamp(float(parts[1].replace("msg=audit(", "").split(":")[0])).strftime("%d.%m.%Y, %H:%M:%S")
                        username = parts[7].replace("acct=", "")
                        ipAddress = parts[10].replace("addr=", "")
                        result = parts[12].replace("res=", "")
                        log_content += f" User {username} from {ipAddress} at {timestamp} has {result}\n"

    except FileNotFoundError:
        log_content = "No log file found."

    # Return the processed log content as part of the HTTP response
    return HttpResponse(f"<pre>{log_content}</pre>")