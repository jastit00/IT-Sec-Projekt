
from collections import defaultdict
from incident_detector.services.utils import format_timedelta
from log_processor.models import UserLogin
from incident_detector.models import (
    BruteforceIncident,
    RelatedLog
)

def detect_bruteforce(config):
    """
    Purpose:
    Detects and logs incidents for brute force attacks.
    
    How:
    Counts number of logins for the same account within a set time window.

    Returns:
    dict {"bruteforce": <number of incidents created>, "incidents": <list with all the new created incidents>}
    """

    BRUTE_FORCE_ATTEMPT_THRESHOLD = config['attempt_threshold']
    BRUTE_FORCE_TIME_DELTA = config['time_delta']
    REPEAT_THRESHOLD = config['repeat_threshold']


    all_logins = UserLogin.objects.all().order_by('timestamp')
    incidents_created = 0
    new_incidents = []

    # Group login attempts by (username, IP address)
    login_groups = defaultdict(list)
    for attempt in all_logins:
        key = (attempt.username, attempt.src_ip_address)
        login_groups[key].append(attempt)

    # Check each user-IP group for brute-force behavior
    for (username, src_ip_address), attempts in login_groups.items():
        if len(attempts) < BRUTE_FORCE_ATTEMPT_THRESHOLD:
            continue

        start = 0
        while start <= len(attempts) - BRUTE_FORCE_ATTEMPT_THRESHOLD:
            window_start = attempts[start].timestamp
            window_end = window_start + BRUTE_FORCE_TIME_DELTA

            # Gather all login attempts within the time window
            window_attempts = []
            current = start
            while current < len(attempts) and attempts[current].timestamp <= window_end:
                window_attempts.append(attempts[current])
                current += 1

            if len(window_attempts) >= BRUTE_FORCE_ATTEMPT_THRESHOLD:
                successful = [attempt for attempt in window_attempts if attempt.result == "success"]

                if successful:
                    severity = "critical"
                    event_time = successful[-1].timestamp 
                    reason = f"{len(window_attempts)} attempts in {format_timedelta(BRUTE_FORCE_TIME_DELTA)}, {len(successful)} successful"
                else:
                    severity = "high"
                    event_time = window_attempts[-1].timestamp
                    reason = f"{len(window_attempts)} failed attempts in {format_timedelta(BRUTE_FORCE_TIME_DELTA)}"

                # Check if a similar incident was already recorded near this time
                if not BruteforceIncident.objects.filter(
                    username=username,
                    src_ip_address=src_ip_address,
                    incident_type="bruteforce",
                    timestamp__gte=event_time - REPEAT_THRESHOLD,
                    timestamp__lte=event_time + REPEAT_THRESHOLD,
                   
                ).exists():
                    incident = BruteforceIncident.objects.create(
                        timestamp=event_time,
                        username=username,
                        src_ip_address=src_ip_address,
                        reason=reason,
                        severity=severity,
                        successful = str(len(successful)),
                        timeDelta=BRUTE_FORCE_TIME_DELTA,
                        attempts=str( len(window_attempts)),

                    )

                    incidents_created += 1
                    new_incidents.append(incident)
                    related_logs = [ RelatedLog(bruteforce_incident=incident, user_login=login_attempt) for login_attempt in window_attempts ]
                    RelatedLog.objects.bulk_create(related_logs)

                start = current  # Move to the end of the current window
            else:
                start += 1  # Not enough attempts — shift window forward
    return {"brute_force": incidents_created, "incidents": new_incidents}