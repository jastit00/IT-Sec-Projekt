from datetime import timedelta
from log_processor.models import UserLogin, UserLogout, UsysConfig , NetfilterPackets, UploadedLogFile
from incident_detector.models import Incident, RelatedLog, DDosIncident, DosIncident,BruteforceIncident,ConfigIncident,ConcurrentLoginIncident
from collections import defaultdict



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
    bf_result = detect_bruteforce()
    cc_result = detect_critical_config_change()
    #cl_result = detect_concurrent_logins()
    dos_result = detect_dos_attack()
    ddos_result = detect_ddos_attack()

    counts = {
        "bruteforce": bf_result["bruteforce"],
        "critical_config_change": cc_result["critical_config_change"],
       # "concurrent_logins": cl_result["concurrent_logins"],
        "dos_attack": dos_result["dos_attacks"],
        "ddos_attack": ddos_result["ddos_attacks"]
    }

    all_new_incidents = (
        bf_result["incidents"] +
        cc_result["incidents"] +
       # cl_result["incidents"] +
        dos_result["incidents"]+
        ddos_result["incidents"]
    )

    return {
        "counts": counts,
        "incidents": all_new_incidents
    }


def detect_bruteforce():
    """
    Detects brute force login attempts by identifying repeated login attempts
    from the same user and IP address within a short time window.

    Returns:
        dict: {"bruteforce": <number_of_incidents_created>}
    """
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
                    timestamp=event_time
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
                start = current  # Move to the end of the current window
            else:
                start += 1  # Not enough attempts — shift window forward

    return {"bruteforce": incidents_created, "incidents": new_incidents}

def detect_critical_config_change():
    """
    Detects and logs incidents for critical configuration changes based on predefined rules.

    Returns:
        dict: Dictionary containing the number of critical config change incidents created.
    """
    all_config_changes = UsysConfig.objects.all().order_by('timestamp')
    incidents_created = 0
    new_incidents = []
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
        src_ip_address = login.src_ip_address if login else None

        severity = "high" if config_change.result == "success" else "critical"
        reason = f"{config_change.action} on {config_change.key} (critical config, result: {config_change.result}, user: {config_change.terminal})"

        if not ConfigIncident.objects.filter(
            timestamp=config_change.timestamp,
            username=config_change.terminal,
            src_ip_address=src_ip_address,
            incident_type="config_change"
        ).exists():
            incident = ConfigIncident.objects.create(
                timestamp=config_change.timestamp,
                username=config_change.terminal,
                src_ip_address=src_ip_address,
                reason=reason,
                severity=severity,
            
            )
            
            new_incidents.append(incident)
            incidents_created += 1
             
    return {"critical_config_change": incidents_created, "incidents": new_incidents}

def detect_concurrent_logins():
    """
    Detects and logs simultaneous logins without a corresponding logout.

    Returns:
        dict: Number of simultaneous login incidents created.
  
    new_incidents=[]
    all_successful_logins=UserLogin.objects.all().filter(result="success")
    potential_used_accounts=[]
    for login in all_successful_logins:
        if (UserLogout.objects.all().filter(terminal=login.terminal).count())==0:
            if login.username in potential_used_accounts:
                if not ConcurrentLoginIncident.objects.filter(username=login.username, ip_address=login.ip_address, reason="Sucessful Simultaneous Login").exists():
                    incident = Incident.objects.create(
                        timestamp=login.timestamp,
                        username=login.username,
                        ip_address=login.ip_address,
                        reason="Sucessful Simultaneous Login"
                    ) # rest of attributes take default values
                    RelatedLog.objects.bulk_create([RelatedLog.(incident=incident,user_login=login)])
                    new_incidents.append(incident)
            else:
                potential_used_accounts.append(login.username)
    return {"simultaneous_logins":len(simultaneous_logins_incidents), "incidents":new_incidents}

"""



def detect_dos_attack():
    """
    Detects potential DoS attacks based on aggregated packet counts in time windows.
    Assumes each NetfilterPackets entry already represents a 30s window with 'count' value.
    """
    all_windows = NetfilterPackets.objects.all().order_by('timestamp')
    packets_by_connection = defaultdict(list)
    last_incident_time = {}
    incidents_created = 0
    new_incidents = []

    for window in all_windows:
        key = (window.src_ip_address, window.dst_ip_address, window.protocol)
        packets_by_connection[key].append(window)

    for (src_ip, dst_ip, protocol), windows in packets_by_connection.items():
        i = 0
        while i < len(windows):
            window_start = windows[i].timestamp
            window_end = window_start + DOS_TIME_DELTA

            # Aggregiere alle Fenster innerhalb des Zeitraums
            relevant_windows = [w for w in windows[i:] if w.timestamp <= window_end]
            total_packets = sum(w.count for w in relevant_windows)

            if total_packets >= DOS_PACKET_THRESHOLD:
                last_time = last_incident_time.get((src_ip, dst_ip))
                reason = f"{total_packets} packets in {format_timedelta(DOS_TIME_DELTA)}"

                existing_incident = DosIncident.objects.filter(
                    src_ip_address=src_ip,
                    dst_ip_address=dst_ip,
                    timestamp__range=(window_start, window_end),
                    incident_type="dos",
                ).exists()

                if not existing_incident and (not last_time or window_start > last_time + DOS_REPEAT_THRESHOLD):
                    incident = DosIncident.objects.create(
                        timestamp=relevant_windows[-1].timestamp,
                        src_ip_address=src_ip,
                        dst_ip_address=dst_ip,
                        reason=reason,
                        incident_type="dos",
                        severity="high",
                        packets=str(total_packets),
                        timeDelta=format_timedelta(DOS_TIME_DELTA),
                        protocol=protocol,
                    )
                    last_incident_time[(src_ip, dst_ip)] = relevant_windows[-1].timestamp
                    incidents_created += 1
                    new_incidents.append(incident)

                # i um alle Fenster innerhalb dieses Zeitraums weiterschieben
                i += len(relevant_windows)
            else:
                i += 1

    return {"dos_attacks": incidents_created, "incidents": new_incidents}







def detect_ddos_attack():
    """
    Detects potential DDoS attacks based on multiple sources sending high packet counts
    to the same destination within a short time window.
    Each NetfilterPackets entry represents a 30s window with a 'count' value.
    """
    all_windows = NetfilterPackets.objects.all().order_by('timestamp')
    windows_by_dst_proto = defaultdict(list)
    last_incident_time = {}
    incidents_created = 0
    new_incidents = []

    # Gruppiere Pakete nach Ziel-IP und Protokoll
    for window in all_windows:
        key = (window.dst_ip_address, window.protocol)
        windows_by_dst_proto[key].append(window)

    for (dst_ip, protocol), windows in windows_by_dst_proto.items():
        i = 0
        while i < len(windows):
            window_start = windows[i].timestamp
            window_end = window_start + DDOS_TIME_DELTA

            # Filtere Fenster im aktuellen Zeitintervall
            relevant_windows = [w for w in windows[i:] if w.timestamp <= window_end]

            # Gruppiere nach Quell-IP
            traffic_by_source = defaultdict(int)
            for win in relevant_windows:
                traffic_by_source[win.src_ip_address] += win.count

            # Zähle Quellen mit signifikantem Verkehr
            active_sources = [src for src, count in traffic_by_source.items() if count >= DDOS_PACKET_THRESHOLD]

            if len(active_sources) >= DDOS_MIN_SOURCES:
                last_time = last_incident_time.get(dst_ip)
                reason = f"{len(active_sources)} sources sent >= {DDOS_PACKET_THRESHOLD} packets in {format_timedelta(DDOS_TIME_DELTA)}"

                existing_incident = DDosIncident.objects.filter(
                    dst_ip_address=dst_ip,
                    timestamp__range=(window_start, window_end),
                    incident_type="ddos",
                ).exists()

                if not existing_incident and (not last_time or window_start > last_time + DDOS_REPEAT_THRESHOLD):
                    # Clean und join sources als String
                    clean_sources = [str(src) for src in active_sources if src]
                    sources_str = ",".join(clean_sources) if clean_sources else "unknown"

                    incident = DDosIncident.objects.create(
                        timestamp=relevant_windows[-1].timestamp,
                        sources=sources_str,
                        dst_ip_address=dst_ip,
                        reason=reason,
                        incident_type="ddos",
                        severity="high",
                        packets=str(sum(traffic_by_source.values())),
                        timeDelta=format_timedelta(DDOS_TIME_DELTA),
                        protocol=protocol,
                    )
                    last_incident_time[dst_ip] = relevant_windows[-1].timestamp
                    incidents_created += 1
                    new_incidents.append(incident)

                # i um alle Fenster innerhalb dieses Zeitraums weiterschieben
                i += len(relevant_windows)
            else:
                i += 1

    return {
        "ddos_attacks": incidents_created,
        "incidents": new_incidents
        
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
