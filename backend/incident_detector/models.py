from django.db import models
from log_processor.models import UserLogin, UserLogout, UsysConfig, NetfilterPackets, UploadedLogFile

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


class DosIncident(models.Model):
    timestamp = models.DateTimeField()
    src_ip_address = models.GenericIPAddressField()
    dst_ip_address = models.GenericIPAddressField(null=True, blank=True)
    timeDelta = models.CharField(max_length=20)
    event_type = models.CharField(max_length=50, default='incident')  
    severity = models.CharField(max_length=20, default='critical') 
    incident_type = models.CharField(max_length=20, default='dos') 
    packets=models.CharField(max_length=20) 
    protocol = models.CharField(max_length=10)
    reason = models.TextField()
    def __str__(self):
        return f"{self.reason} from {self.src_ip_address} at {self.timestamp}"


class DDosIncident(models.Model):
    timestamp = models.DateTimeField()
    dst_ip_address = models.GenericIPAddressField(null=True, blank=True)
    timeDelta = models.CharField(max_length=20)
    event_type = models.CharField(max_length=50, default='incident')  
    severity = models.CharField(max_length=20, default='critical') 
    incident_type = models.CharField(max_length=20, default='ddos') 
    packets=models.CharField(max_length=20) 
    protocol = models.CharField(max_length=10)
    reason = models.TextField()
    sources = models.CharField(max_length=10)
    def __str__(self):
     return f"{self.reason} targeting {self.dst_ip_address} at {self.timestamp}"

class LoginIncident(models.Model):
    timestamp = models.DateTimeField()
    src_ip_address = models.GenericIPAddressField(null=True, blank=True)
    username = models.CharField(max_length=100)
    reason = models.TextField()
    event_type = models.CharField(max_length=50, default='incident')  
    severity = models.CharField(max_length=20, default='critical') 
    incident_type = models.CharField(max_length=20, default='concurrentLogin') 
    def __str__(self):
       return f"{self.username} at {self.timestamp} from {self.src_ip_address}"

class ConfigIncident(models.Model):
    timestamp = models.DateTimeField()
    src_ip_address = models.GenericIPAddressField(null=True, blank=True)
    username = models.CharField(max_length=100)
    reason = models.TextField()
    event_type = models.CharField(max_length=50, default='incident')  
    severity = models.CharField(max_length=20, default='critical') 
    incident_type = models.CharField(max_length=20, default='configchange') 
    def __str__(self):
       return f"{self.username} at {self.timestamp} from {self.src_ip_address}"

class BruteforceIncident(models.Model):
    timestamp = models.DateTimeField()
    src_ip_address = models.GenericIPAddressField(null=True, blank=True)
    username = models.CharField(max_length=100)
    reason = models.TextField()
    attempts= models.CharField(max_length=100)
    timeDelta = models.CharField(max_length=20)
    successful= models.CharField(max_length=20)
    event_type = models.CharField(max_length=50, default='incident')  
    severity = models.CharField(max_length=20, default='critical') 
    incident_type = models.CharField(max_length=20, default='configchange') 
    def __str__(self):
       return f"{self.username} at {self.timestamp} from {self.src_ip_address}"





class RelatedLog(models.Model):
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='related_logs_set')
    log_file = models.ForeignKey(UploadedLogFile, on_delete=models.CASCADE, related_name='related_logs_set',null=True)
    
    # Optional foreign keys - one of these will be set
    user_login = models.ForeignKey(UserLogin, on_delete=models.SET_NULL, null=True, blank=True)
    usys_config = models.ForeignKey(UsysConfig, on_delete=models.SET_NULL, null=True, blank=True)
    netfilter_packet = models.ForeignKey(NetfilterPackets, on_delete=models.SET_NULL, null=True, blank=True)
    
    
    def __str__(self):
        if self.user_login:
            return f"Login log from {self.user_login.username}"
        elif self.usys_config:
            return f"Config change {self.usys_config.action} on {self.usys_config.key}"
        elif self.netfilter_packet:
            return f"Packet from {self.netfilter_packet.src_ip_address} to {self.netfilter_packet.dst_ip_address}"
        return "Related log"