from incident_detector.models import (
    ConcurrentLoginIncident,
    RelatedLog,
)
from log_processor.models import (
    UserLogin,
    UserLogout
)

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
    incidents_created = 0
    successful_logins=UserLogin.objects.filter(result="success")
    for login in successful_logins:
        if login.username in potential_used_accounts:
            if (
                (UserLogout.objects.filter(terminal=potential_used_accounts[login.username]).count()==1) and 
                (UserLogout.objects.filter(terminal=potential_used_accounts[login.username]).first().timestamp < login.timestamp)
               ):
                potential_used_accounts[login.username]=login.terminal
            else:
                if not ConcurrentLoginIncident.objects.filter(
                    src_ip_address=login.src_ip_address,
                    username=login.username,
                    incident_type="concurrentLogin"
                    ).exists():
                    incident = ConcurrentLoginIncident.objects.create(
                        timestamp=login.timestamp,
                        username=login.username,
                        src_ip_address=login.src_ip_address,
                        reason="user logged in again without previous logout"
                    )
                    incidents_created += 1

                    new_incidents.append(incident)

                    RelatedLog.objects.create(concurrent_login_incident=incident, user_login=login)
        else:
            potential_used_accounts[login.username]=login.terminal
    
    return {"concurrent_logins": len(new_incidents), "incidents": new_incidents}
