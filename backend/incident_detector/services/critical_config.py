

from incident_detector.models import (
    ConfigIncident, 
)
from log_processor.models import (
    UsysConfig,
    UserLogin,
)

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
            result="success",
            timestamp__lte=config_change.timestamp
        ).order_by('-timestamp').first()
        src_ip_address = login.src_ip_address if login else None

        severity = "high" if config_change.result == "success" else "critical"
        reason = f"{config_change.action} on {config_change.key} (critical config, result: {config_change.result}, user: {config_change.terminal})"

        if not ConfigIncident.objects.filter(
            timestamp=config_change.timestamp,
            username=config_change.terminal,
            reason=reason,
            src_ip_address=src_ip_address,
            incident_type="configchange"
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
