from django.conf import settings 
import os
from django.shortcuts import render
from django.http import HttpResponse

# Create your views here.
LOG_FILE_PATH = os.path.join(settings.BASE_DIR, '..', 'logs', 'brute_force_example.log')


def process_log(request):
    # Initialize a variable to store log content
    log_content = ""

    try:
        # Read the log file
        with open(LOG_FILE_PATH, 'r') as log_file:
            # Get the first 10 lines for testing
            lines = log_file.readlines()
            log_content = "\n".join(lines[:10])  # Join the first 10 lines with line breaks

    except FileNotFoundError:
        log_content = "Log file not found."

    # Return the log content as part of the HTTP response
    return HttpResponse(f"<pre>{log_content}</pre>")