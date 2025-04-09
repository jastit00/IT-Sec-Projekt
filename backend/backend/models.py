from django.db import models

# Create your models here.
class User_Login(models.Model):
    log_type = models.CharField(max_length=50) 
    timestamp = models.DateTimeField()
    account = models.CharField(max_length=100)
    address = models.GenericIPAddressField()
    result = models.CharField(max_length=20)

    def __str__(self):
        return f"{self.timestamp} - {self.account} - {self.result}"