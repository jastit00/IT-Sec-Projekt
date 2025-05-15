from django.db import models
from log_processor.models import User_Login, User_Logout, Usys_Config, NetfilterPkt, UploadedLogFile

# Create your models here.
class Incident(models.Model):
    timestamp = models.DateTimeField()
    username = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()
    reason = models.TextField()
    event_type = models.CharField(max_length=50, default='incident')  
    severity = models.CharField(max_length=20, default='critical') 
    def __str__(self):
        return f"{self.reason} from {self.ip_address} at {self.timestamp} with {self.username}"

class Related_Log(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='related_logs_set')
    log_file = models.ForeignKey(UploadedLogFile, on_delete=models.CASCADE, related_name='related_logs_set',null=True)
    
    # Optional foreign keys - one of these will be set
    user_login = models.ForeignKey(User_Login, on_delete=models.SET_NULL, null=True, blank=True)
    usys_config = models.ForeignKey(Usys_Config, on_delete=models.SET_NULL, null=True, blank=True)
    netfilter_pkt = models.ForeignKey(NetfilterPkt, on_delete=models.SET_NULL, null=True, blank=True)

    
    def __str__(self):
        if self.user_login:
            return f"Login log from {self.user_login.username}"
        elif self.usys_config:
            return f"Config change {self.usys_config.action} on {self.usys_config.key}" 