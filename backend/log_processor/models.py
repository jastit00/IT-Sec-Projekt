from django.db import models


class User_Login(models.Model):
    log_type = models.CharField(max_length=50)
    timestamp = models.DateTimeField()
    username = models.CharField(max_length=100)
    ipAddress = models.GenericIPAddressField()
    result = models.CharField(max_length=20)
    
    def __str__(self):
        return f"{self.username} at {self.timestamp} from {self.ipAddress}"