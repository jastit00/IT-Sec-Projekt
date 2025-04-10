from django.db import models
from log_processor.models import User_Login

# Create your models here.
class Incident(models.Model):
    timestamp = models.DateTimeField()
    username = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()
    reason = models.TextField()
    related_logs = models.ManyToManyField(User_Login)
    
    def __str__(self):
        return f"{self.reason} from {self.ip_address} at {self.timestamp} withg {self.username}"

        