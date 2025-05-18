from rest_framework import serializers
from .models import Incident,DosIncident
from log_processor.serializers import UserLoginSerializer

class IncidentSerializer(serializers.ModelSerializer):
    related_logs = UserLoginSerializer(many=True, read_only=True)

    class Meta:
        model = Incident
        fields = '__all__'

class DosIncidentSerializer(serializers.ModelSerializer):
    # related_logs = UserLoginSerializer(many=True, read_only=True)
    class Meta:
        model = DosIncident
        fields = '__all__'
