from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User

class UserLogin(models.Model):
    timestamp = models.DateTimeField()
    username = models.CharField(max_length=32)
    src_ip_address = models.GenericIPAddressField()
    terminal = models.CharField(max_length=4, null=True)
    result = models.CharField(max_length=16)
    event_type = models.CharField(max_length=16, default='login',)  
    severity = models.CharField(max_length=16, default='normal') 
    def __str__(self):
        return f"Login from {self.username} at {self.timestamp} from {self.src_ip_address} on terminal {self.terminal}"

class UserLogout(models.Model):
    timestamp = models.DateTimeField()
    username = models.CharField(max_length=32)
    terminal = models.CharField(max_length=4, null=True)
    result = models.CharField(max_length=16)
    event_type = models.CharField(max_length=16, default='logout')
    severity = models.CharField(max_length=16, default='normal')
    def __str__(self):
        return f"Logout from {self.username} at {self.timestamp} on terminal {self.terminal}"

class UsysConfig(models.Model):
    timestamp = models.DateTimeField()
    table = models.CharField(max_length=32)
    action = models.CharField(max_length=16)
    key = models.CharField(max_length=100, null=True)
    value = models.TextField(null=True)
    condition = models.CharField(max_length=64, null=True) 
    terminal = models.CharField(max_length=32)
    result = models.CharField(max_length=16)
    event_type = models.CharField(max_length=16, default='config change')
    severity = models.CharField(max_length=16, default='normal')
    def __str__(self):
        return f"{self.action} {self.key} at {self.timestamp} with value {self.value}"

class UploadedLogFile(models.Model):
    filename = models.CharField(max_length=255)
    file_hash = models.CharField(max_length=64, unique=True)
    source = models.CharField(max_length=100, default='unknown')
    uploaded_by = models.CharField(max_length=150, null=True)
    uploaded_at = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=16)
    entries_created = models.IntegerField(default=0)
    incidents_created_total = models.IntegerField(default=0)
    incident_counts = models.JSONField(default=dict, null=True)
    keycloakUser= models.CharField(max_length=150, null=True)
    def __str__(self):
        return f"{self.filename} uploaded by {self.uploaded_by} at {self.uploaded_at}"
    
class NetfilterPackets(models.Model):
    timestamp = models.DateTimeField()
    src_ip_address = models.GenericIPAddressField()
    dst_ip_address = models.GenericIPAddressField()
    protocol = models.CharField(max_length=8)
    event_type = models.CharField(max_length=16, default='network packets')
    count = models.IntegerField(default=0)   
    severity = models.CharField(max_length=16, default='normal')
    def __str__(self):
        return f"{self.src_ip_address} to {self.dst_ip_address} at {self.timestamp}"
    

class DetectionConfig(models.Model):
    key = models.CharField(max_length=100, unique=True)
    data = models.JSONField()   
    updated_at = models.DateTimeField(auto_now=True)  

    def __str__(self):
        return f"{self.key} updated at {self.updated_at}"
