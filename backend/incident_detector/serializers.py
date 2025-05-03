from rest_framework import serializers
from .models import Incident
from log_processor.serializers import UserLoginSerializer

class IncidentSerializer(serializers.ModelSerializer):
    related_logs = UserLoginSerializer(many=True, read_only=True)

    class Meta:
        model = Incident
        fields = '__all__'
