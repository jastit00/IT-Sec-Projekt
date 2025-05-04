import os
import tempfile
import logging
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

from log_processor.services import process_log_file
from log_processor.models import UploadedLogFile, User_Login, Usys_Config
from log_processor.serializers import LogFileSerializer, UserLoginSerializer, UsysConfigSerializer
from incident_detector.models import Incident
from incident_detector.serializers import IncidentSerializer

logger = logging.getLogger(__name__)#für den ligger name falls was schief geht einfacher einsehbar wo

class LogFileUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, *args, **kwargs):#später erweiterbar
        uploaded_file = request.FILES.get('file')
        source = request.data.get('source', 'unknown')

        if not uploaded_file:
            logger.warning("Upload attempt without file.")
            return Response({"status": "error", "message": "Please upload a file"}, status=status.HTTP_400_BAD_REQUEST)

        if not uploaded_file.name.endswith('.log'):
            logger.warning("Upload attempt with invalid file type.")
            return Response({"status": "error", "message": "Only .log files are allowed."}, status=status.HTTP_400_BAD_REQUEST)

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            for chunk in uploaded_file.chunks():
                temp_file.write(chunk)
            file_path = temp_file.name

        try:
            result = process_log_file(file_path)
        except Exception as e:
            logger.exception("Error while processing log file.")
            os.unlink(file_path)
            return Response({"status": "error", "message": "Failed to process audit log file."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        finally:
            if os.path.exists(file_path):
                os.unlink(file_path)

        uploaded_log_file = UploadedLogFile(
            filename=uploaded_file.name,
            source=source,
            uploaded_by=request.user if request.user.is_authenticated else None,
            uploaded_at=timezone.now(),
            status='success' if result.get('status') != 'error' else 'error'  # <- Direkt hier berechnen
        )
        uploaded_log_file.save()

        serializer = LogFileSerializer(uploaded_log_file)
        data = serializer.data
        filtered_data = {
        'id': data.get('id'),
        'status': data.get('status'),
        'file': data.get('file'),
        'name': data.get('name'),
         }

        logger.info(f"Audit log uploaded by {request.user.username if request.user.is_authenticated else 'anonymous'}: {uploaded_file.name}")
        return Response(filtered_data, status=status.HTTP_200_OK)


@api_view(['GET'])
def processed_logins(request):
    start = request.query_params.get('start')
    end = request.query_params.get('end')
    queryset = User_Login.objects.all()
    if start:
        queryset = queryset.filter(timestamp__gte=start)
    if end:
        queryset = queryset.filter(timestamp__lte=end)
    serializer = UserLoginSerializer(queryset, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def processed_config_changes(request):
    start = request.query_params.get('start')
    end = request.query_params.get('end')
    queryset = Usys_Config.objects.all()
    if start:
        queryset = queryset.filter(timestamp__gte=start)
    if end:
        queryset = queryset.filter(timestamp__lte=end)
    serializer = UsysConfigSerializer(queryset, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def processed_incidents(request):
    start = request.query_params.get('start')
    end = request.query_params.get('end')
    queryset = Incident.objects.all()
    if start:
        queryset = queryset.filter(timestamp__gte=start)
    if end:
        queryset = queryset.filter(timestamp__lte=end)
    serializer = IncidentSerializer(queryset, many=True)
    return Response(serializer.data)


#import os
#import tempfile
#from django.http import JsonResponse
#from django.views.decorators.csrf import csrf_exempt
#from .services import process_log_file

# TODO maybe add try/except block to catch more errors and return them in the response
#@csrf_exempt # disable CSRF protection -> maybe change it later -> angular
#def upload_log_file(request):
#   if request.method == 'POST' and 'file' in request.FILES:
#       uploaded_file = request.FILES['file']
#     
#       # Save uploaded file to a temporary location
#       temp_file = tempfile.NamedTemporaryFile(delete=False)
#       file_path = temp_file.name
# 
#       # Write the uploaded file to the temporary file
#       for chunk in uploaded_file.chunks():
#           temp_file.write(chunk)
#       temp_file.close()
#       
#       # Process the file using the existing function
#       result = process_log_file(file_path)
#       
#       # Clean up
#       os.unlink(file_path)
#       
#       return JsonResponse(result)
#   return JsonResponse({"status": "error", "message": "Please upload a file"}, status=400)
