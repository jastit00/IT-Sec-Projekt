import copy
import logging
from collections import defaultdict
from datetime import timedelta

from django.forms.models import model_to_dict
from django.utils.timezone import now

from incident_detector.models import (
    BruteforceIncident,
    ConfigIncident,
    ConcurrentLoginIncident,
    DDosIncident,
    DosIncident,
    
)
from log_processor.models import (
    NetfilterPackets,
    UsysConfig,
    UserLogin,
    UserLogout,
    DetectionConfig
)

logger = logging.getLogger(__name__)

# --- Default Configs ---
BRUTE_FORCE_DEFAULT = {
    'attempt_threshold': 10,
    'time_delta': 120,
    'repeat_threshold': 600,
}

DOS_DEFAULT = {
    'packet_threshold': 100,
    'time_delta': 10,
    'repeat_threshold': 120,
}

DDOS_DEFAULT = {
    'packet_threshold': 10,
    'time_delta': 2,
    'repeat_threshold': 60,
    'min_sources': 2,
}

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

def get_current_config():
    try:
        obj = DetectionConfig.objects.get(key="current")
        return obj.data, obj.updated_at
    except DetectionConfig.DoesNotExist:
        default = {
            "brute_force": BRUTE_FORCE_DEFAULT,
            "dos": DOS_DEFAULT,
            "ddos": DDOS_DEFAULT,
        }
        obj = DetectionConfig.objects.create(key="current", data=default)
        return obj.data, obj.updated_at

def save_new_config(new_config):
    obj, created = DetectionConfig.objects.update_or_create(
        key="current",
        defaults={"data": new_config}
    )
    # Optional: hier Incidents löschen / neu erzeugen
    return obj.updated_at

def convert_if_needed(value):
    if not isinstance(value, timedelta):
        return timedelta(seconds=value)
    return value

def load_config(config):
    """
    Wandelt JSON-konforme Config in passende Typen um.
    Gibt die fertige Config zurück (kein globaler State mehr).
    """
    config = copy.deepcopy(config)

    config["brute_force"]["time_delta"] = convert_if_needed(config["brute_force"]["time_delta"])
    config["brute_force"]["repeat_threshold"] = convert_if_needed(config["brute_force"]["repeat_threshold"])
    config["dos"]["time_delta"] = convert_if_needed(config["dos"]["time_delta"])
    config["dos"]["repeat_threshold"] = convert_if_needed(config["dos"]["repeat_threshold"])
    config["ddos"]["time_delta"] = convert_if_needed(config["ddos"]["time_delta"])
    config["ddos"]["repeat_threshold"] = convert_if_needed(config["ddos"]["repeat_threshold"])

    return config





def update_config(new_config):
    """
    Speichert neue Config, löscht bei Änderungen entsprechende Incidents,
    lädt die Config neu und startet Incident Detection mit der neuen Config.
    """
    # Alte Config aus DB holen
    old_config_raw, _ = get_current_config()
    old_config = load_config(old_config_raw)
    new_config_loaded = load_config(new_config)

    changes = {
        "brute_force": old_config["brute_force"] != new_config_loaded["brute_force"],
        "dos": old_config["dos"] != new_config_loaded["dos"],
        "ddos": old_config["ddos"] != new_config_loaded["ddos"],
    }

    if not any(changes.values()):
        return {"message": "Config values are the same. No update performed.", "changed": False}

    # Config speichern
    save_new_config(new_config)

    # Lösche Incidents bei geänderten Kategorien
    if changes["brute_force"]:
        BruteforceIncident.objects.all().delete()
    if changes["dos"]:
        DosIncident.objects.all().delete()
    if changes["ddos"]:
        DDosIncident.objects.all().delete()

    changed_categories = [cat for cat, changed in changes.items() if changed]

    # Incident Detection mit neuer Config starten
    result = detect_incidents(categories=changed_categories, config=new_config_loaded)

    return {
        "message": "Config updated; incidents deleted and re-detected where needed.",
        "changed": True,
        "total_incidents": sum(result["counts"].values()),
        "result": result,
        "config": new_config_loaded,
    }

def detect_incidents(categories=None, config=None):
    """
    Führt die Incident Detection für gegebene Kategorien und Config aus.
    Lädt Config falls nicht gegeben.
    """
    if categories is None:
        categories = ["brute_force", "critical_config_change", "concurrent_logins", "dos", "ddos"]

    if config is None:
        config_raw, _ = get_current_config()
        config = load_config(config_raw)

    bf_result = {"brute_force": 0, "incidents": []}
    cc_result = {"critical_config_change": 0, "incidents": []}
    cl_result = {"concurrent_logins": 0, "incidents": []}
    dos_result = {"dos": 0, "incidents": []}
    ddos_result = {"ddos": 0, "incidents": []}

    if "brute_force" in categories:
        bf_result = detect_bruteforce(config["brute_force"])

    if "critical_config_change" in categories:
        cc_result = detect_critical_config_change()

    if "concurrent_logins" in categories:
        cl_result = detect_concurrent_logins()

    if "dos" in categories:
        dos_result = detect_dos_attack(config["dos"])

    if "ddos" in categories:
        ddos_result = detect_ddos_attack(config["ddos"])

    counts = {
        "brute_force": bf_result["brute_force"],
        "critical_config_change": cc_result["critical_config_change"],
        "concurrent_logins": cl_result["concurrent_logins"],
        "dos": dos_result["dos"],
        "ddos": ddos_result["ddos"]
    }

    all_new_incidents = (
        bf_result["incidents"] +
        cc_result["incidents"] +
        cl_result["incidents"] +
        dos_result["incidents"] +
        ddos_result["incidents"]
    )
    all_new_incidents_serialized = [model_to_dict(inc) for inc in all_new_incidents]

    return {
        "counts": counts,
        "incidents": all_new_incidents_serialized,
    }

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
                # Move to the end of the current window
                start = current  
            else:
                # Not enough attempts — shift window forward
                start += 1

    return {"brute_force": incidents_created, "incidents": new_incidents}

def detect_critical_config_change():
    """
    Purpose:
    Detects and logs incidents for critical configuration changes based on predefined rules.
    
    How:
    Cheks whether certain config changes, categorized as critical, were performed.

    Returns:
        dict {"critical_config_change": <number of incidents created>, "incidents": <list with all the new created incidents>}
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
        ).order_by("-timestamp").first()
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


def detect_dos_attack(config):
    """
    Detects potential DoS attacks based on aggregated packet counts in time windows.
    Assumes each NetfilterPackets entry already represents a 30s window with 'count' value.
    """
    DOS_PACKET_THRESHOLD = config['packet_threshold']
    DOS_TIME_DELTA = config['time_delta']
    DOS_REPEAT_THRESHOLD = config['repeat_threshold']

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

            # get packets w/in current set time window
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

                # slide time window
                i += len(relevant_windows)
            else:
                i += 1

    return {"dos": incidents_created, "incidents": new_incidents}



def detect_ddos_attack(config):
    """
    Detects potential DDoS attacks based on multiple sources sending high packet counts
    to the same destination within a short time window.
    Each NetfilterPackets entry represents a 30s window with a 'count' value.
    """
    DDOS_PACKET_THRESHOLD = config['packet_threshold']
    DDOS_TIME_DELTA = config['time_delta']
    DDOS_REPEAT_THRESHOLD = config['repeat_threshold']
    DDOS_MIN_SOURCES = config['min_sources']

    all_windows = NetfilterPackets.objects.all().order_by('timestamp')
    windows_by_dst_proto = defaultdict(list)
    last_incident_time = {}
    incidents_created = 0
    new_incidents = []

    # grouping packets by source IP address and protocol
    for window in all_windows:
        key = (window.dst_ip_address, window.protocol)
        windows_by_dst_proto[key].append(window)

    for (dst_ip, protocol), windows in windows_by_dst_proto.items():
        i = 0
        while i < len(windows):
            window_start = windows[i].timestamp
            window_end = window_start + DDOS_TIME_DELTA

            # get packets w/in current set time window
            relevant_windows = [w for w in windows[i:] if w.timestamp <= window_end]

            # count packets per IP address
            traffic_by_source = defaultdict(int)
            for win in relevant_windows:
                traffic_by_source[win.src_ip_address] += win.count

            # get IP address that sent significant amount of packets
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
                    # formatting source IP addresses
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

                # slide time window
                i += len(relevant_windows)
            else:
                i += 1

    return {
        "ddos": incidents_created,
        "incidents": new_incidents
        
    }


def detect_concurrent_logins():
    """
    Purpose:
    Detect and log incidents for simutaneous logins.
    
    How:
    Checks whether before next login of the same account a logout or a session termination happened.
    Session terminations have in logs type USER_END but are stored in the db as USER_LOGOUT.
    
    Returns:
    dict {"concurrent_logins": <number of incidents created>, "incidents": <list with all the new created incidents>}
    """
    new_incidents=[]
    potential_used_accounts={}
    successful_logins=UserLogin.objects.filter(result="success")
    for login in successful_logins:
        if login.username in potential_used_accounts:
            if (
                (UserLogout.objects.filter(terminal=potential_used_accounts[login.username]).count()==1) and 
                (UserLogout.objects.filter(terminal=potential_used_accounts[login.username]).first().timestamp < login.timestamp)
               ):
                potential_used_accounts[login.username]=login.terminal
            else:
                if not ConcurrentLoginIncident.objects.filter(src_ip_address=login.src_ip_address,
                    username=login.username,
                    incident_type="concurrentLogin"
                    ).exists():
                    incident = ConcurrentLoginIncident.objects.create(
                        timestamp=login.timestamp,
                        username=login.username,
                        src_ip_address=login.src_ip_address,
                        reason="user logged in again without previous logout"
                    )

                    new_incidents.append(incident)
            else:
                potential_used_accounts.append(login.username)

    return {"concurrent_logins": len(new_incidents), "incidents": new_incidents}


def format_timedelta(delta):
    """
    Purpose:
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

