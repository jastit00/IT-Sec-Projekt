from django.utils.decorators import method_decorator
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework import status
from .validation import keycloak_required
from log_processor.serializers import LogFileSerializer
from log_processor.services import handle_uploaded_log_file
import logging

logger = logging.getLogger(__name__)

@method_decorator(keycloak_required, name='dispatch')
class LogFileUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, *args, **kwargs):
        uploaded_file = request.FILES.get('file')
        source = request.data.get('source', 'unknown')

        # Authentifizierter Benutzer aus Keycloak
        keycloak_user = request.keycloak_user
        uploaded_by_user = keycloak_user.get('preferred_username') 
        if not uploaded_file:
            logger.warning("Upload attempt without file.")
            return Response({"status": "error", "message": "Please upload a file"}, status=status.HTTP_400_BAD_REQUEST)

        if not uploaded_file.name.endswith('.log'):
            logger.warning("Upload attempt with invalid file type.")
            return Response({"status": "error", "message": "Only .log files are allowed."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            result = handle_uploaded_log_file(uploaded_file, source, uploaded_by_user,keycloak_user)
        except Exception as e:
            logger.exception("Error while processing log file.")
            return Response({"status": "error", "message": "Failed to process audit log file."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        if result["status"] == "duplicate":
            logger.warning(f"Duplicate file upload attempt: {uploaded_file.name}")
            return Response({"status": "error", "message": "Diese Datei wurde bereits hochgeladen."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = LogFileSerializer(result["uploaded_log_file"])
        data = serializer.data

        filtered_data = {
            'id': data.get('id'),
            'status': data.get('status'),
            'filename': data.get('filename'),
            'entries_created': data.get('entries_created', 0),
            'incidents_created_total': data.get('incidents_created_total', 0),
            'incident_counts': data.get('incident_counts', {}),
        }

        logger.info(f"Audit log uploaded by {uploaded_by_user}: {uploaded_file.name}")
        return Response(filtered_data, status=status.HTTP_200_OK)