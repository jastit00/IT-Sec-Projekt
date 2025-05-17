from django.db import models
from log_processor.models import UserLogin, UserLogout, UsysConfig, NetfilterPacket, UploadedLogFile

# Create your models here.
class Incident(models.Model):
    timestamp = models.DateTimeField()
    username = models.CharField(max_length=100)
    src_ip_address = models.GenericIPAddressField()
    dst_ip_address = models.GenericIPAddressField(null=True, blank=True)
    reason = models.TextField()
    event_type = models.CharField(max_length=50, default='incident')  
    severity = models.CharField(max_length=20, default='critical') 
    incident_type = models.CharField(max_length=20, default='boese') 
    def __str__(self):
        return f"{self.reason} from {self.src_ip_address} at {self.timestamp} with {self.username}"

class RelatedLog(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='related_logs_set')
    log_file = models.ForeignKey(UploadedLogFile, on_delete=models.CASCADE, related_name='related_logs_set',null=True)
    
    # Optional foreign keys - one of these will be set
    user_login = models.ForeignKey(UserLogin, on_delete=models.SET_NULL, null=True, blank=True)
    usys_config = models.ForeignKey(UsysConfig, on_delete=models.SET_NULL, null=True, blank=True)
    netfilter_packet = models.ForeignKey(NetfilterPacket, on_delete=models.SET_NULL, null=True, blank=True)
    
    
    def __str__(self):
        if self.user_login:
            return f"Login log from {self.user_login.username}"
        elif self.usys_config:
            return f"Config change {self.usys_config.action} on {self.usys_config.key}"
        elif self.netfilter_packet:
            return f"Packet from {self.netfilter_packet.source_ip} to {self.netfilter_packet.destination_ip}"
        return "Related log"