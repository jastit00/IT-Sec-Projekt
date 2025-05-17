from rest_framework import serializers
from .models import UserLogin, UserLogout, UsysConfig, NetfilterPacket
from django.utils import timezone
class UserLoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserLogin
        fields = '__all__'

class UserLogoutSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserLogout
        fields = '__all__'

class UsysConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = UsysConfig
        fields = '__all__'
        
class NetfilterPacketSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetfilterPacket
        fields = '__all__'

    def get_changedSettings(self, obj):
        return [f"{obj.table}:{obj.key}={obj.value}"]

class LogFileSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    filename = serializers.CharField(read_only=True)
    file_hash = serializers.CharField(max_length=64)
    source = serializers.CharField(required=False)
    uploaded_by = serializers.CharField(read_only=True)
    uploaded_at = serializers.DateTimeField(read_only=True, default=timezone.now)
    status = serializers.ChoiceField(choices=['success', 'error'], read_only=True)
