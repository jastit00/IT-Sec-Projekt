from datetime import timedelta
#from django.shortcuts import render
#from django.http import JsonResponse
from log_processor.models import UserLogin, UserLogout, UsysConfig , NetfilterPacket, UploadedLogFile
from incident_detector.models import Incident, RelatedLog,DDosIncident,DosIncident
from collections import defaultdict
#from django.utils import timezone




BRUTE_FORCE_ATTEMPT_THRESHOLD = 10
BRUTE_FORCE_TIME_DELTA = timedelta(minutes=2)
BRUTE_FORCE_REPEAT_THRESHOLD = timedelta(minutes=10)

DOS_TIME_DELTA = timedelta(seconds=10)             # Zeitfenster zur Erkennung eines Angriffs
DOS_REPEAT_THRESHOLD = timedelta(minutes=2)        # Mindestabstand, bis erneut ein Angriff für dieselbe Quelle/Ziel erkannt wird
DOS_PACKET_THRESHOLD = 100       

DDOS_PACKET_THRESHOLD = 10
DDOS_TIME_DELTA = timedelta(seconds=2)
DDOS_REPEAT_THRESHOLD = timedelta(seconds=60)
DDOS_MIN_SOURCES = 2

# vars for critical config change detection
CRITICAL_CONFIG_RULES = [
    {
        "table": "config",
        "action": "update",
        "key": "password_policy",
    },
    {
        "table": "users",
        "action": "update",
        "key": "password_changetime",
    },
]



def detect_incidents():
    return {
        "incidents": {
            "bruteforce": detect_bruteforce()["bruteforce"],
            "critical_config_change": detect_critical_config_change()["critical_config_change"],
            "concurrent_logins": detect_concurrent_logins()["concurrent_logins"],
            "dos_attack": detect_dos_attack()["dos_attacks"],
            "ddos_attack": detect_ddos_attack()["ddos_attacks"]
        }
    }




def format_timedelta(delta):
    """
    Converts a timedelta object into a short  string.
    
    Parameters:
        delta (timedelta): The timedelta object to format.
    
    Returns:
        str: a string of minutes and seconds.
    """
    seconds = int(delta.total_seconds())
    minutes, seconds = divmod(seconds, 60)
    if minutes and seconds:
        return f"{minutes} minutes and {seconds} seconds"
    elif minutes:
        return f"{minutes} minutes"
    else:
        return f"{seconds} seconds"

def detect_bruteforce():
    """
    Detects brute force login attempts by identifying repeated login attempts
    from the same user and IP address within a short time window.

    Returns:
        dict: {"bruteforce": <number_of_incidents_created>}
    """
    all_logins = UserLogin.objects.all().order_by('timestamp')
    incidents_created = 0

    # Group login attempts by (username, IP address)
    login_groups = defaultdict(list)
    for attempt in all_logins:
        key = (attempt.username, attempt.ip_address)
        login_groups[key].append(attempt)

    # Check each user-IP group for brute-force behavior
    for (username, ip_address), attempts in login_groups.items():
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
                if not Incident.objects.filter(
                    username=username,
                    src_ip_address=ip_address,
                    incident_type="bruteforce",
                    timestamp=event_time
                ).exists():
                    incident = Incident.objects.create(
                        timestamp=event_time,
                        username=username,
                        src_ip_address=ip_address,
                        reason=reason,
                        severity=severity,
                        incident_type="bruteforce"
                    )

                    RelatedLog.objects.bulk_create([
                        RelatedLog(incident=incident, user_login=attempt)
                        for attempt in window_attempts
                    ])

                    incidents_created += 1

                start = current  # Move to the end of the current window
            else:
                start += 1  # Not enough attempts — shift window forward

    return {"bruteforce": incidents_created}

def detect_critical_config_change():
    """
    Detects and logs incidents for critical configuration changes based on predefined rules.

    Returns:
        dict: Dictionary containing the number of critical config change incidents created.
    """
    all_config_changes = UsysConfig.objects.all().order_by('timestamp')
    incidents_created = 0

    for config_change in all_config_changes:
        is_critical = False
        for rule in CRITICAL_CONFIG_RULES:
            if (
                ("table" not in rule or rule["table"] == config_change.table) and
                ("action" not in rule or rule["action"] == config_change.action) and
                ("key" not in rule or rule["key"] == config_change.key) and
                ("value" not in rule or rule["value"] == config_change.value)
            ):
                is_critical = True
                break

        if not is_critical:
            continue

        login = UserLogin.objects.filter(
            username=config_change.terminal,
            timestamp__lte=config_change.timestamp
        ).order_by('-timestamp').first()
        src_ip_address = login.ip_address if login else None

        severity = "high" if config_change.result == "success" else "critical"
        reason = f"{config_change.action} on {config_change.key} (critical config, result: {config_change.result}, user: {config_change.terminal})"

        if not Incident.objects.filter(
            timestamp=config_change.timestamp,
            username=config_change.terminal,
            src_ip_address=src_ip_address,
            incident_type="config_change"
        ).exists():
            incident = Incident.objects.create(
                timestamp=config_change.timestamp,
                username=config_change.terminal,
                src_ip_address=src_ip_address,
                reason=reason,
                severity=severity,
                incident_type="config_change"
            )

            RelatedLog.objects.bulk_create([
                RelatedLog(incident=incident, usys_config=config_change)
            ])

        incidents_created += 1

    return {"critical_config_change": incidents_created}

def detect_concurrent_logins():
    """
    Detects and logs simultaneous logins without a corresponding logout.

    Returns:
        dict: Number of simultaneous login incidents created.
    """
    incidents_created = 0
    active_user_sessions = {}  # username -> IP

    successful_logins = UserLogin.objects.filter(result="success").order_by("timestamp")

    for login in successful_logins:
        logout_found = UserLogout.objects.filter(
            terminal=login.terminal,
            timestamp__gt=login.timestamp
        ).exists()

        if not logout_found:
            if login.username in active_user_sessions:
                previous_ip = active_user_sessions[login.username]

                # Prepare reason based on IP match
                if login.ip_address == previous_ip:
                    reason = f"{login.username} logged in from same IP {login.ip_address} without logout"
                    severity = "medium"
                else:
                    reason = f"{login.username} logged in from {login.ip_address} (prev: {previous_ip}) without logout"
                    severity = "high"

                if not Incident.objects.filter(
                    username=login.username,
                    src_ip_address=login.ip_address,
                    incident_type="concurrent_login"
                ).exists():
                    incident = Incident.objects.create(
                        timestamp=login.timestamp,
                        username=login.username,
                        src_ip_address=login.ip_address,
                        reason=reason,
                        severity=severity,
                        incident_type="concurrent_login"
                    )

                    RelatedLog.objects.bulk_create([
                        RelatedLog(incident=incident, user_login=login)
                    ])

                    incidents_created += 1
            else:
                # First time we've seen a login without logout for this user
                active_user_sessions[login.username] = login.ip_address

    return {"concurrent_logins": incidents_created}

def detect_dos_attack():
    """
    Detects potential DoS attacks based on the number of packets sent in a specified time window.
    """
    all_packets = NetfilterPacket.objects.all().order_by('timestamp')
    dos_incidents_created = 0

    last_incident_time = {}
    packets_by_connection = defaultdict(list)

    for packet in all_packets:
        key = (packet.source_ip, packet.destination_ip)
        packets_by_connection[key].append(packet)

    for (src_ip, dst_ip), packets in packets_by_connection.items():
        i = 0
        while i < len(packets) - DOS_PACKET_THRESHOLD + 1:
            window_start = packets[i].timestamp
            window_end = window_start + DOS_TIME_DELTA
            window_packets = [pkt for pkt in packets[i:] if pkt.timestamp <= window_end]

            if len(window_packets) >= DOS_PACKET_THRESHOLD:
                last_time = last_incident_time.get((src_ip, dst_ip))
                reason = f"{len(window_packets)} packets in {format_timedelta(DOS_TIME_DELTA)}"

                existing_incident = DosIncident.objects.filter(
                    src_ip_address=src_ip,
                    dst_ip_address=dst_ip,
                    timestamp__range=(window_start, window_end),
                    incident_type="dos",
                ).exists()

                if not existing_incident and (not last_time or window_start > last_time + DOS_REPEAT_THRESHOLD):
                    protocols_in_window = set(pkt.protocol for pkt in window_packets)
                    protocols_str = ", ".join(sorted(protocols_in_window))
                    DosIncident.objects.create(
                        timestamp=window_packets[-1].timestamp,
                        src_ip_address=src_ip,
                        dst_ip_address=dst_ip,
                        reason=reason,
                        incident_type="dos",
                        severity="high",
                        packets=str(len(window_packets)),
                        timeDelta=format_timedelta(DOS_TIME_DELTA),
                        protocol=protocols_str,
                    )
                    last_incident_time[(src_ip, dst_ip)] = window_packets[-1].timestamp
                    dos_incidents_created += 1

                i += len(window_packets)
            else:
                i += 1

    return {"dos_attacks": dos_incidents_created}

def detect_ddos_attack():
    """
    Detects potential DDoS attacks by evaluating packets from multiple sources to the same destination.
    """
    all_packets = NetfilterPacket.objects.all().order_by('timestamp')
    ddos_incidents_created = 0

    last_incident_time = {}
    packets_by_target = defaultdict(list)

    for packet in all_packets:
        packets_by_target[packet.destination_ip].append(packet)

    for dst_ip, packets in packets_by_target.items():
        i = 0
        while i < len(packets) - DDOS_PACKET_THRESHOLD + 1:
            window_start = packets[i].timestamp
            window_end = window_start + DDOS_TIME_DELTA
            window_packets = [pkt for pkt in packets[i:] if pkt.timestamp <= window_end]
            source_ips_in_window = set(pkt.source_ip for pkt in window_packets)

            if len(window_packets) >= DDOS_PACKET_THRESHOLD and len(source_ips_in_window) >= DDOS_MIN_SOURCES:
                last_time = last_incident_time.get(dst_ip)

                existing_incident = DDosIncident.objects.filter(
                    dst_ip_address=dst_ip,
                    timestamp__range=(window_start, window_end),
                ).exists()

                if not existing_incident and (not last_time or window_start > last_time + DDOS_REPEAT_THRESHOLD):
                    protocols_in_window = set(pkt.protocol for pkt in window_packets)
                    protocols_str = ", ".join(sorted(protocols_in_window))
                    DDosIncident.objects.create(
                        timestamp=window_packets[-1].timestamp,
                        dst_ip_address=dst_ip,
                        timeDelta=str(DDOS_TIME_DELTA),
                        event_type="incident",
                        severity="critical",
                        incident_type="ddos",
                        packets=str(len(window_packets)),
                        protocol=protocols_str,
                        reason=(
                            f"Potential DDoS attack - {len(window_packets)} packets "
                            f"from {len(source_ips_in_window)} sources in {DDOS_TIME_DELTA.total_seconds()}s"
                        ),
                        sources=str(len(source_ips_in_window)),
                    )
                    last_incident_time[dst_ip] = window_packets[-1].timestamp
                    ddos_incidents_created += 1

                i += len(window_packets)
            else:
                i += 1

    return {"ddos_attacks": ddos_incidents_created}


