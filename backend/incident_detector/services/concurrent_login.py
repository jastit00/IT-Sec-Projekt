from incident_detector.models import (
    ConcurrentLoginIncident,
    RelatedLog,
)
from log_processor.models import (
    UserLogin,
    UserLogout,
)


def detect_concurrent_logins():
    """
    Detects and logs simultaneous logins without a corresponding logout.

    Returns:
        dict: Number of simultaneous login incidents created.
    """
    new_incidents = []
    potential_used_accounts=[]
    successful_logins = UserLogin.objects.all().filter(result="success")
    for login in successful_logins:
        if (UserLogout.objects.filter(terminal=login.terminal).count())==0:
            if login.username in potential_used_accounts:
                if not ConcurrentLoginIncident.objects.filter(src_ip_address=login.src_ip_address,username=login.username,incident_type="concurrentLogin").exists():
                    incident = ConcurrentLoginIncident.objects.create(timestamp=login.timestamp,username=login.username,src_ip_address=login.src_ip_address,reason="user logged in again without previous logout")
                    new_incidents.append(incident)

                    RelatedLog.objects.create(concurrent_login_incident=incident, user_login=login)
            else:
                potential_used_accounts.append(login.username)
    
    return {"concurrent_logins": len(new_incidents), "incidents": new_incidents}