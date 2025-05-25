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
