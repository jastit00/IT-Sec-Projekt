from django.db import models
from log_processor.models import UserLogin, UserLogout, UsysConfig, NetfilterPackets, UploadedLogFile


class DosIncident(models.Model):
    timestamp = models.DateTimeField()
    timeDelta = models.CharField(max_length=32)
    src_ip_address = models.GenericIPAddressField()
    dst_ip_address = models.GenericIPAddressField()
    event_type = models.CharField(max_length=16, default='incident')  
    severity = models.CharField(max_length=16, default='critical') 
    incident_type = models.CharField(max_length=16, default='dos') 
    packets = models.IntegerField(default=0) 
    protocol = models.CharField(max_length=8)
    reason = models.TextField()
    def __str__(self):
        return f"{self.reason} from {self.src_ip_address} to {self.dst_ip_address} at {self.timestamp}"

class DDosIncident(models.Model):
    timestamp = models.DateTimeField()
    timeDelta = models.CharField(max_length=32)
    dst_ip_address = models.GenericIPAddressField()
    event_type = models.CharField(max_length=16, default='incident')  
    severity = models.CharField(max_length=16, default='critical') 
    incident_type = models.CharField(max_length=16, default='ddos') 
    packets = models.IntegerField(default=0) 
    protocol = models.CharField(max_length=8)
    reason = models.TextField()
    sources = models.TextField()
    def __str__(self):
     return f"[{self.timestamp}] DDoS on {self.dst_ip_address} ({self.protocol})"

class ConcurrentLoginIncident(models.Model):
    timestamp = models.DateTimeField()
    src_ip_address = models.GenericIPAddressField()
    username = models.CharField(max_length=32)
    reason = models.TextField()
    event_type = models.CharField(max_length=16, default='incident')  
    severity = models.CharField(max_length=16, default='critical') 
    incident_type = models.CharField(max_length=16, default='concurrentLogin') 
    def __str__(self):
        return f"{self.reason} at {self.timestamp} by {self.username} from {self.src_ip_address}"

class ConfigIncident(models.Model):
    timestamp = models.DateTimeField()
    src_ip_address = models.GenericIPAddressField()
    username = models.CharField(max_length=32)
    reason = models.TextField()
    event_type = models.CharField(max_length=16, default='incident')  
    severity = models.CharField(max_length=16, default='critical') 
    incident_type = models.CharField(max_length=16, default='configchange') 
    def __str__(self):
        return f"{self.reason} at {self.timestamp} by {self.username} from {self.src_ip_address}"

class BruteforceIncident(models.Model):
    timestamp = models.DateTimeField()
    timeDelta = models.CharField(max_length=32)
    src_ip_address = models.GenericIPAddressField()
    username = models.CharField(max_length=32)
    reason = models.TextField()
    attempts = models.IntegerField(default=0)   
    successful= models.IntegerField(default=0) 
    event_type = models.CharField(max_length=16, default='incident')  
    severity = models.CharField(max_length=16, default='critical') 
    incident_type = models.CharField(max_length=16, default='bruteforce')
    def __str__(self):
        return f"{self.reason} from {self.src_ip_address} at {self.timestamp} with {self.username} ({self.attempts} attempts, {self.successful} successful)"


class RelatedLog(models.Model):
    # Point to one specific incident model (only one per row)
    dos_incident = models.ForeignKey('DosIncident', on_delete=models.CASCADE, null=True)
    ddos_incident = models.ForeignKey('DDosIncident', on_delete=models.CASCADE, null=True)
    bruteforce_incident = models.ForeignKey('BruteforceIncident', on_delete=models.CASCADE, null=True)
    concurrent_login_incident = models.ForeignKey('ConcurrentLoginIncident', on_delete=models.CASCADE, null=True)
    config_incident = models.ForeignKey('ConfigIncident', on_delete=models.CASCADE, null=True)

    user_login = models.ForeignKey(UserLogin, on_delete=models.SET_NULL, null=True)
    user_logout = models.ForeignKey(UserLogout, on_delete=models.SET_NULL, null=True,)
    usys_config = models.ForeignKey(UsysConfig, on_delete=models.SET_NULL, null=True)
    netfilter_packet = models.ForeignKey(NetfilterPackets, on_delete=models.SET_NULL, null=True)
    def __str__(self):
        incident_str = ""
        if self.dos_incident:
            incident_str = f"DOS Incident: {self.dos_incident}"
        elif self.ddos_incident:
            incident_str = f"DDoS Incident: {self.ddos_incident}"
        elif self.bruteforce_incident:
            incident_str = f"Bruteforce Incident: {self.bruteforce_incident}"
        elif self.concurrent_login_incident:
            incident_str = f"Concurrent Login Incident: {self.concurrent_login_incident}"
        elif self.config_incident:
            incident_str = f"Config Change Incident: {self.config_incident}"
        else:
            incident_str = "No incident"
        return f"{incident_str}"

