from rest_framework import serializers

from .models import (
    UserLogin,
    UserLogout,
    UsysConfig,
    NetfilterPackets,
    UploadedLogFile,
)


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

    def get_changed_settings(self, obj):
        return [f"{obj.table}:{obj.key}={obj.value}"]


class NetfilterPacketsSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetfilterPackets
        fields = '__all__'


class LogFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadedLogFile
        fields = '__all__'
