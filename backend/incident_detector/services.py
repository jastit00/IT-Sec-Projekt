from datetime import timedelta, datetime
from django.shortcuts import render
from django.http import JsonResponse
from .models import User_Login, Incident


# Threshold vars for brute force
BRUTE_FORCE_ATTEMPT_THRESHOLD = 12
BRUTE_FORCE_TIME_DELTA = timedelta(minutes=5)

# Create your views here.
def detect_incidents():
    bruteforce_incidents = detect_bruteforce()
    
    #########################################
    # TODO
    # Placeholder other detections
    #detect_unauthorized_config_change()
    #detect_concurrent_logins()
    #
    #########################################

    return {"incidents": bruteforce_incidents}

def detect_bruteforce():
    all_logins = User_Login.objects.all().order_by('timestamp')
    bruteforce_incidents_created = 0  # Initialize incident counter
    # Login attempts by user/ip
    login_attempts_by_user_ip = {}

    # First, loop through all logins to create a dict of login attempts by user/ip
    for login in all_logins:
        key = (login.username, login.ipAddress)
        
        # Create the list of login attempts for each user/ip
        if key not in login_attempts_by_user_ip:
            login_attempts_by_user_ip[key] = []
        login_attempts_by_user_ip[key].append(login)

    # Second, loop through the login attempts to find brute force attempts
    for (username, ip), attempts in login_attempts_by_user_ip.items():
        if len(attempts) < BRUTE_FORCE_ATTEMPT_THRESHOLD:
            continue # Skip if not enough attempts
        
        # Check for sequences of attempts that are within the time window
        i = 0
        while i < len(attempts) - BRUTE_FORCE_ATTEMPT_THRESHOLD + 1:
            window_start = attempts[i].timestamp # Start of the time window
            window_end = window_start + BRUTE_FORCE_TIME_DELTA # End of the time window
            
            # Count attempts in the time window
            j = i
            while j < len(attempts) and attempts[j].timestamp <= window_end:
                j += 1
            
            # If found enough attempts in the time window -> potential bruteforce attempt
            if j - i >= BRUTE_FORCE_ATTEMPT_THRESHOLD:
                attack_attempts = attempts[i:j] # Get the list of attempts in the time window
                
                # Check if the last attempt was successful
                last_attempt = attack_attempts[-1]
                reason = "Potential Successful Brute Force Attempt" if last_attempt.result == "success" else "Potential Failed Brute Force Attempt"
                
                # Create incident for this brute force attempt
                if not Incident.objects.filter(username=username, ip_address=ip, reason=reason).exists():
                    # Create a new incident if it doesn't exist
                    incident = Incident.objects.create(
                        timestamp=last_attempt.timestamp,
                        username=username,
                        ip_address=ip,
                        reason=reason
                    )
                    incident.related_logs.set(attack_attempts) # Link the related logs to the incident
                    bruteforce_incidents_created += 1  # Increment the incident counter

                # Move the index to the end of the current window
                i = j
            else:
                i += 1 # Move to the next attempt

    # Return the count of incidents created
    return  {"bruteforce": bruteforce_incidents_created}
