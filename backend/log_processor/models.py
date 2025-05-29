from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class UserLogin(models.Model):
    timestamp = models.DateTimeField()
    username = models.CharField(max_length=100)
    src_ip_address = models.GenericIPAddressField()
    terminal = models.CharField(max_length=4, blank=True)
    result = models.CharField(max_length=20)
    event_type = models.CharField(max_length=50, default='login',)  
    severity = models.CharField(max_length=20, default='normal') 
    def __str__(self):
       return f"{self.username} at {self.timestamp} from {self.src_ip_address}"

class UserLogout(models.Model):
    timestamp = models.DateTimeField()
    username = models.CharField(max_length=100)
    terminal = models.CharField(max_length=20, blank=True)
    result = models.CharField(max_length=20)
    event_type = models.CharField(max_length=50, default='logout')
    severity = models.CharField(max_length=20, default='normal')
    def __str__(self):
       return f"{self.username} at {self.timestamp}"

class UsysConfig(models.Model):
    timestamp = models.DateTimeField()
    table = models.CharField(max_length=100)
    action = models.CharField(max_length=100)
    key = models.CharField(max_length=100)
    value = models.CharField(max_length=255)
    condition = models.CharField(max_length=100) 
    terminal = models.CharField(max_length=100)
    result = models.CharField(max_length=20)
    event_type = models.CharField(max_length=50, default='config change')
    severity = models.CharField(max_length=20, default='normal')
    def __str__(self):
        return f"{self.action} {self.key} at {self.timestamp} with value {self.value}"

class UploadedLogFile(models.Model):
    filename = models.CharField(max_length=255)
    file_hash = models.CharField(max_length=64, unique=True, null=False)
    source = models.CharField(max_length=100, default='unknown')
    uploaded_by = models.CharField(max_length=150, null=True, blank=True)
    uploaded_at = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=20)
    entries_created = models.IntegerField(default=0)
    incidents_created_total = models.IntegerField(default=0)
# dicts speichern ,  JSONField (ab Django 3.1+)
    incident_counts = models.JSONField(default=dict, blank=True)
    def __str__(self):
        return f"{self.filename} uploaded by {self.uploaded_by} at {self.uploaded_at}"
    
class NetfilterPackets(models.Model):
    timestamp = models.DateTimeField()
    src_ip_address = models.GenericIPAddressField()
    dst_ip_address = models.GenericIPAddressField()
    protocol = models.CharField(max_length=10)
    event_type = models.CharField(max_length=50, default='network packets')
    count = models.IntegerField(default=0)   
    severity = models.CharField(max_length=20, default='normal')
    def __str__(self):
        return f"{self.src_ip_address} to {self.dst_ip_address} at {self.timestamp}"
    

class DetectionConfig(models.Model):
    key = models.CharField(max_length=100, unique=True)
    data = models.JSONField()   # oder TextField mit JSON, je nach DB
    updated_at = models.DateTimeField(auto_now=True)  # speichert automatisch die letzte Änderung

    def __str__(self):
        return f"{self.key} updated at {self.updated_at}"
