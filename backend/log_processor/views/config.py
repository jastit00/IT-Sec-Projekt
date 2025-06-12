import logging

from django.utils.decorators import method_decorator
from rest_framework import status
from rest_framework.response import Response

from incident_detector.serializers import IncidentDetectorConfigSerializer
from incident_detector.services.detection import (
    get_current_config,
    save_new_config,
    update_config,
)

from .validation import keycloak_required

logger = logging.getLogger(__name__)

@method_decorator(keycloak_required, name='dispatch') 

def post(self, request):
    dos_config = request.data.get('dos', {})
    ddos_config = request.data.get('ddos', {})

    dos_time_delta = dos_config.get('time_delta')
    ddos_time_delta = ddos_config.get('time_delta')

    if dos_time_delta is not None:
        try:
            if int(dos_time_delta) < 30:
                return Response({
                    "status": "error",
                    "message": "Must be at least 30 seconds due to 30s packet window."
                }, status=status.HTTP_400_BAD_REQUEST)
        except (ValueError, TypeError):
            return Response({
                "status": "error",
                "message": "dos_time_delta must be an integer."
            }, status=status.HTTP_400_BAD_REQUEST)

    if ddos_time_delta is not None:
        try:
            if int(ddos_time_delta) < 30:
                return Response({
                    "status": "error",
                    "message": "Must be at least 30 seconds due to 30s packet window."
                }, status=status.HTTP_400_BAD_REQUEST)
        except (ValueError, TypeError):
            return Response({
                "status": "error",
                "message": "ddos_time_delta must be an integer."
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = IncidentDetectorConfigSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        new_config = serializer.validated_data
        current_config, _ = get_current_config()

        if current_config == new_config:
            return Response({"message": "Config unchanged"}, status=status.HTTP_200_OK)

        result = update_config(new_config)
        last_updated = save_new_config(new_config)

        return Response({
            "message": result["message"],
            "last_updated": last_updated,
            "changed": result.get("changed", False),
            "total_incidents": result.get("total_incidents", 0),
            "result": result.get("result", {}),
            "config": result.get("config", {}),
        }, status=status.HTTP_200_OK)
