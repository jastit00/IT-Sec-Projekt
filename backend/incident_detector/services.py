from datetime import timedelta, datetime
from django.shortcuts import render
from django.http import JsonResponse
from .models import Incident, Related_Log
from log_processor.models import User_Login, User_Logout, Usys_Config 





BRUTE_FORCE_ATTEMPT_THRESHOLD = 13
BRUTE_FORCE_TIME_DELTA = timedelta(minutes=5)

# vars for critical config change detection
CRITICAL_CONFIG_RULES = [
    {
        "table": "config",
        "action": "update",
        "key": "password_policy",
        "value": "enabled"
    },
    {
        "table": "users",
        "action": "update",
        "key": "password_changetime",
        "value": "*"
    },
]


# Create your views here.
def detect_incidents():
    bruteforce_incidents = detect_bruteforce()
    critical_config_incidents = detect_critical_config_change()
    simultaniousLogins = detect_concurrent_logins()
    
    #########################################
    # TODO
    # Placeholder other detections
    #detect_unauthorized_config_change()
    #detect_concurrent_logins()
    #
    #########################################

    return {"incidents": {
        "bruteforce": bruteforce_incidents["bruteforce"],
        "critical_config_change": critical_config_incidents["critical_config_change"],
        "simultanious_logins": simultaniousLogins["simultaneous_logins"]
}}



def detect_critical_config_change():
    all_config_changes = Usys_Config.objects.all().order_by('timestamp')
    critical_config_incidents_created = 0  # Initialize incident counter
    
    # Loop through all config changes to find critical changes
    for config_change in all_config_changes:
        for rule in CRITICAL_CONFIG_RULES:
            # Check if the rule's table, action, key, and value match 
            if (
                ("table" not in rule or rule["table"] == config_change.table) and
                ("action" not in rule or rule["action"] == config_change.action) and
                ("key" not in rule or rule["key"] == config_change.key) and
                ("value" not in rule or rule["value"] == config_change.value)
                ):
                
                
                # TODO
                # Fetch the most recent login entry for the username before or at the time of the config change -> EDIT THIS IF LOGOUT LOGIC IS WOORKING
                # if we have login / logout tiome windows, we can check if the user was logged in at the time of the config change instead of just the most recent login
                login = User_Login.objects.filter(
                    username=config_change.terminal,
                    timestamp__lte=config_change.timestamp  # "less than or equal" -> login before or at the time of the config change
                ).order_by('-timestamp').first() # this returns the most recent entry
                
                # If a login entry is found, use its IP address; otherwise, set ip_address to None
                ip_address = login.ip_address if login else None





                
                # Ensure ip_address is defined before creating an incident
                if ip_address:
                    # Check if an incident already exists for this change
                    if not Incident.objects.filter(
                        timestamp=config_change.timestamp,
                        username=config_change.terminal,
                        ip_address=ip_address,
                    ).exists():
                        # Create a new incident
                        incident = Incident.objects.create(
                            timestamp=config_change.timestamp,
                            username=config_change.terminal,
                            ip_address=ip_address,
                            reason="Critical Config Change: " + config_change.action + " on " + config_change.key
                            
                        )
                        
                        # Create a RelatedLog entry for the config change
                        Related_Log.objects.create(
                            incident=incident,
                            usys_config=config_change  
                        )
                        critical_config_incidents_created += 1  # Increment the incident counter
    
    return {"critical_config_change": critical_config_incidents_created }




def detect_bruteforce():
    all_logins = User_Login.objects.all().order_by('timestamp')
    bruteforce_incidents_created = 0  # Initialize incident counter
    # Login attempts by user/ip
    login_attempts_by_user_ip_address = {}

    # First, loop through all logins to create a dict of login attempts by user/ip
    for login in all_logins:
        key = (login.username, login.ip_address)
        
        # Create the list of login attempts for each user/ip
        if key not in login_attempts_by_user_ip_address:
            login_attempts_by_user_ip_address[key] = []
        login_attempts_by_user_ip_address[key].append(login)

    # Second, loop through the login attempts to find brute force attempts
    for (username, ip_address), attempts in login_attempts_by_user_ip_address.items():
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
                if not Incident.objects.filter(username=username, ip_address=ip_address, reason=reason).exists():
                    # Create a new incident
                    incident = Incident.objects.create(
                        timestamp=last_attempt.timestamp,
                        username=username,
                        ip_address=ip_address,
                        reason=reason
                    )
                    
                    # Create Related_Log entries for each login attempt
                    for login_attempt in attack_attempts:
                        Related_Log.objects.create(
                            incident=incident,
                            user_login=login_attempt  # Set the user_login field
                        )
                    
                    bruteforce_incidents_created += 1  # Increment the incident counter

                # Move the index to the end of the current window
                i = j
            else:
                i += 1 # Move to the next attempt

    # Return the count of incidents created
    return {"bruteforce": bruteforce_incidents_created}

    # [added 1.05.2025]
# second try implementing this function; hopefully this time works
def detect_concurrent_logins():
    """
    Detects potential security incidents due to multiple simultaneous logins
    from the same terminal. A difference of 2 or more logins vs. logouts
    suggests unauthorized session persistence or credential misuse.
    """
    incidents_created = 0

    # 1. Get all unique terminal values from login table
    #terminals = User_Login.objects.values_list('terminal', flat=True).filter(result="success").distinct()
    usernames=User_Login.objects.values_list('username', flat=True).filter(result="success").distinct()

    # 2. Process each terminal
    for username_value in usernames:
        amount_of_entries_login=User_Login.objects.filter(username=username_value).count()
        amount_of_entries_logout=User_Logout.objects.filter(username=username_value).count()
        
        
        difference = amount_of_entries_login - amount_of_entries_logout




        # 3. Check for suspicious behavior
        if difference >= 2:
            # 4. Get latest login info

            recent_logins = User_Login.objects.filter(username=username_value, result="success")
            username = recent_logins.first().username
            ip=User_Login.objects.values_list('ip_address', flat=True)[0]
            #terminal=User_Login.objects.values_list('terminal', flat=True)[0]

            # 5. Prevent duplicate incidents
            if not Incident.objects.filter(username=username, ip_address=ip, reason="Simultanious logins").exists():
                incident=Incident.objects.create(timestamp=User_Login.objects.values_list('timestamp', flat=True).filter(username=username).order_by('timestamp').first(),username=username,ip_address=ip,
                                                reason="Simultanious logins" + " from " + str(difference) + " different terminals" + " with " + str(amount_of_entries_login-difference) + " logins and " + str(amount_of_entries_logout) + " logouts"
                    )
                
                latest_logins = User_Login.objects.order_by('-timestamp')[:difference]
                
                for login in latest_logins:
                    Related_Log.objects.create(
                        incident=incident,
                        user_login=login
                )
                
                #incident.set(User_Login.objects.values().order_by('-timestamp')[0:difference])
                # attach the logins (we don't know how many, it can be 2 or more -> 0 to x where x is excluded) that are at the very top when listing (we order them by the timestamp in descending order -> oldest timestamp below)
                incidents_created+=1 # adding one incident created to the counter

    # 6. Return incident count
    return {"simultaneous_logins": incidents_created}
