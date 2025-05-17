from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class UserLogin(models.Model):
    timestamp = models.DateTimeField()
    username = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()
    terminal = models.CharField(max_length=4, blank=True)
    result = models.CharField(max_length=20)
    event_type = models.CharField(max_length=50, default='login')  
    severity = models.CharField(max_length=20, default='normal') 
    def __str__(self):
       return f"{self.username} at {self.timestamp} from {self.ip_address}"

class UserLogout(models.Model):
    timestamp = models.DateTimeField()
    username = models.CharField(max_length=100)
    terminal = models.CharField(max_length=4)  
    result = models.CharField(max_length=20)
    event_type = models.CharField(max_length=50, default='logout')  # NEU
    severity = models.CharField(max_length=20, default='normal')
    def __str__(self):
       return f"{self.username} at {self.timestamp} from {self.ipAddress}"

class UsysConfig(models.Model):
    timestamp = models.DateTimeField()
    table = models.CharField(max_length=100)
    action = models.CharField(max_length=100)
    key = models.CharField(max_length=100)
    value = models.CharField(max_length=255)
    condition = models.CharField(max_length=100) 
    terminal = models.CharField(max_length=100)
    result = models.CharField(max_length=20)
    event_type = models.CharField(max_length=50, default='config change')  # NEU
    severity = models.CharField(max_length=20, default='normal')
    
class UploadedLogFile(models.Model):
    filename = models.CharField(max_length=255)
    file_hash = models.CharField(max_length=64, unique=True, null=False)
    source = models.CharField(max_length=100, default='unknown')
    uploaded_by = models.CharField(max_length=150, null=True, blank=True)
    uploaded_at = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=20)
    
    def __str__(self):
        return f"{self.action} {self.key} at {self.timestamp} with value {self.value}"

class NetfilterPacket(models.Model):
    timestamp = models.DateTimeField()
    source_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    protocol = models.CharField(max_length=10)
    event_type = models.CharField(max_length=50, default='network packet')  # NEU
    severity = models.CharField(max_length=20, default='normal')
    def __str__(self):
        return f"{self.source_ip} to {self.destination_ip} at {self.timestamp}"
    