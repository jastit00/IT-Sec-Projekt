import copy
from django.forms.models import model_to_dict
from incident_detector.services.dos import detect_dos_attack
from incident_detector.services.critical_config import  detect_critical_config_change
from incident_detector.services.bruteforce import detect_bruteforce
from incident_detector.services.concurrent_login import detect_concurrent_logins
from incident_detector.services.ddos import detect_ddos_attack
from datetime import timedelta


from incident_detector.models import (
    BruteforceIncident,
    DDosIncident,
    DosIncident,   
)
from log_processor.models import (
    DetectionConfig
)

BRUTE_FORCE_DEFAULT = {
    'attempt_threshold': 10,
    'time_delta': 120,
    'repeat_threshold': 600,
}

DOS_DEFAULT = {
    'packet_threshold': 100,
    'time_delta': 30,
    'repeat_threshold': 120,
}

DDOS_DEFAULT = {
    'packet_threshold': 30,
    'time_delta': 30,
    'repeat_threshold': 60,
    'min_sources': 2,
}

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
