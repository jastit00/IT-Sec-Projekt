from rest_framework import serializers

from .models import (
    DosIncident,
    DDosIncident,
    ConfigIncident,
    ConcurrentLoginIncident,
    BruteforceIncident,
)

from log_processor.serializers import UserLoginSerializer


class DosIncidentSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = DosIncident
        fields = '__all__'


class DDosIncidentSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = DDosIncident
        fields = '__all__'

class ConfigIncidentSerializer(serializers.ModelSerializer):
  
    class Meta:
        model = ConfigIncident
        fields = '__all__'
    
class ConcurrentLoginIncidentSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = ConcurrentLoginIncident
        fields = '__all__'


class BruteforceIncidentSerializer(serializers.ModelSerializer):
  
    class Meta:
        model = BruteforceIncident
        fields = '__all__'


class BruteForceConfigSerializer(serializers.Serializer):
    attempt_threshold = serializers.IntegerField(default=10)
    time_delta = serializers.IntegerField(default=120)  # Sekunden
    repeat_threshold = serializers.IntegerField(default=600)  # Sekunden

class DoSConfigSerializer(serializers.Serializer):
    packet_threshold = serializers.IntegerField(default=100)
    time_delta = serializers.IntegerField(default=30)  # Sekunden
    repeat_threshold = serializers.IntegerField(default=120)  # Sekunden

class DDoSConfigSerializer(serializers.Serializer):
    packet_threshold = serializers.IntegerField(default=10)
    time_delta = serializers.IntegerField(default=30)  # Sekunden
    repeat_threshold = serializers.IntegerField(default=60)  # Sekunden
    min_sources = serializers.IntegerField(default=2)

class IncidentDetectorConfigSerializer(serializers.Serializer):
    brute_force = BruteForceConfigSerializer(required=False, default={
        'attempt_threshold': 10,
        'time_delta': 120,
        'repeat_threshold': 600,
    })
    dos = DoSConfigSerializer(required=False, default={
        'packet_threshold': 100,
        'time_delta': 30,
        'repeat_threshold': 120,
    })
    ddos = DDoSConfigSerializer(required=False, default={
        'packet_threshold': 30,
        'time_delta': 30,
        'repeat_threshold': 60,
        'min_sources': 2,
    })