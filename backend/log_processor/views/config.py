import logging

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from incident_detector.serializers import (
    IncidentDetectorConfigSerializer,
)
from incident_detector.services.detection import (
    get_current_config,
    save_new_config,
    update_config,
)



logger = logging.getLogger(__name__)


class IncidentConfigAPIView(APIView):
    def post(self, request):

      
        dos_config = request.data.get('dos', {})
        
        dos_time_delta = dos_config.get('time_delta')
        

        errors = {}

        if dos_time_delta is not None and dos_time_delta < 30:
            errors['dos.time_delta'] = "Must be at least 30 seconds due to 30s packet window."

      

        if errors:
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)

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
