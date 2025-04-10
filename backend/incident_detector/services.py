from datetime import timedelta, datetime
from django.shortcuts import render
from django.http import JsonResponse
from .models import User_Login, Incident


# Threshold vars for brute force
BRUTE_FORCE_ATTEMPT_THRESHOLD = 10
BRUTE_FORCE_TIME_DELTA = timedelta(minutes=5)

# Create your views here.
def detect_incidents():
    brute_force_incidents = detect_bruteforce()
    
    # Placeholder other detections
    #detect_unauthorized_config_change()
    #detect_concurrent_logins()

    incidents_created = brute_force_incidents
    return {"incidents": incidents_created}

def detect_bruteforce():
    all_logins = User_Login.objects.all().order_by('timestamp')

    # Login attempts by user/ip
    login_attempts_by_user_ip = {}

    # First, loop through all logins to create a dict of login attempts by user/ip
    for login in all_logins:
        key = (login.username, login.ipAddress)
        
        # Create the list of login attempts for each user/ip
        if key not in login_attempts_by_user_ip:
            login_attempts_by_user_ip[key] = []
        login_attempts_by_user_ip[key].append(login)

    incidents_created = 0  # Initialize incident counter

    for (username, ip), attempts in login_attempts_by_user_ip.items():
        # Skip if not enough attempts to be considered brute force
        if len(attempts) < BRUTE_FORCE_ATTEMPT_THRESHOLD:
            continue
        
        # Check for sequences of attempts that occur close together
        i = 0
        while i < len(attempts) - BRUTE_FORCE_ATTEMPT_THRESHOLD + 1:
            # Check if we have enough consecutive attempts within the time window
            window_start = attempts[i].timestamp
            window_end = window_start + BRUTE_FORCE_TIME_DELTA
            
            # Count attempts in this sliding window
            j = i
            while j < len(attempts) and attempts[j].timestamp <= window_end:
                j += 1
            
            # If we found enough attempts in this window, it's a potential brute force
            if j - i >= BRUTE_FORCE_ATTEMPT_THRESHOLD:
                # Consider all attempts from the start of the window to the last sequential attempt
                attack_attempts = attempts[i:j]
                
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
                    incident.related_logs.set(attack_attempts)

                    incidents_created += 1  # Increment the incident counter

                # Skip ahead past this attack to avoid creating multiple incidents for the same attack
                i = j
            else:
                # Move forward one attempt at a time
                i += 1

    # Return the count of incidents created
    return incidents_created
