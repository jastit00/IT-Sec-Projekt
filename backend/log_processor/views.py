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
from log_processor.models import UploadedLogFile, User_Login, Usys_Config,User_Logout
from log_processor.serializers import LogFileSerializer, UserLoginSerializer, UsysConfigSerializer,UserLogoutSerializer
from incident_detector.models import Incident
from incident_detector.serializers import IncidentSerializer
from django.views.decorators.csrf import csrf_exempt
import hashlib
from incident_detector.services import CRITICAL_CONFIG_RULES;

logger = logging.getLogger(__name__)#für den ligger name falls was schief geht einfacher einsehbar wo


class LogFileUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    @csrf_exempt
    
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
            hasher = hashlib.sha256()
            for chunk in uploaded_file.chunks():
                hasher.update(chunk)
                temp_file.write(chunk)
            file_hash = hasher.hexdigest()
            file_path = temp_file.name
         

        if UploadedLogFile.objects.filter(file_hash=file_hash).exists():
            logger.warning(f"Duplicate file upload attempt: {uploaded_file.name}")
            os.unlink(file_path)
            return Response(
                {"status": "error", "message": "Diese Datei wurde bereits hochgeladen."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            result = process_log_file(file_path)
        except Exception as e:
            logger.exception("Error while processing log file.")
            os.unlink(file_path)
            return Response({"status": "error", "message": "Failed to process audit log file."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        finally:
            if os.path.exists(file_path):
                os.unlink(file_path)

        # Benutzer aus der HTTP-Anfrage extrahieren
        uploaded_by_user = request.data.get('uploaded_by', 'anonym')
        uploaded_log_file = UploadedLogFile(
            filename=uploaded_file.name,
            file_hash=file_hash,
            source=source,
            uploaded_by=uploaded_by_user,
            uploaded_at=timezone.now(),
            status='success' if result.get('status') != 'error' else 'error'  # <- Direkt hier berechnen
        )
        uploaded_log_file.save()

        serializer = LogFileSerializer(uploaded_log_file)
        data = serializer.data
        filtered_data = {
        'id': data.get('id'),
        'status': data.get('status'),
        'filename': data.get('filename'),
        
         }

    
        logger.info(f"Audit log uploaded by {uploaded_by_user}: {uploaded_file.name}")
        return Response(filtered_data, status=status.HTTP_200_OK)

@csrf_exempt
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

@csrf_exempt
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

@csrf_exempt
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

@api_view(['GET'])
def unified_event_log(request):
    # Daten sammeln
    incidents = Incident.objects.all()
    user_logins = User_Login.objects.all()
    user_logouts = User_Logout.objects.all()
    usys_configs = Usys_Config.objects.all()

    # Serialisieren
    incident_data = IncidentSerializer(incidents, many=True).data
    login_data = UserLoginSerializer(user_logins, many=True).data
    logout_data = UserLogoutSerializer(user_logouts, many=True).data
    config_data = UsysConfigSerializer(usys_configs, many=True).data

    # Event-Typ hinzufügen
    for entry in incident_data:
        entry['event_type'] = 'incident'
        entry['severity'] = 'critical'

    for entry in login_data:
        entry['event_type'] = 'login'
        entry['severity'] = 'normal' if entry.get('result') == 'success' else 'warning'
        
    for entry in logout_data:
        entry['event_type'] = 'logout'
        entry['severity'] = 'normal' if entry.get('result') == 'success' else 'warning'
 
    for entry in config_data:
        entry['event_type'] = 'config'
        
  
        if entry.get("result") == "success":
            entry['severity'] = 'normal'  # Erfolg -> normale Schwere
        else:
            entry['severity'] = 'warning'  # Fehler -> Warnung


 
    # Alle Daten zusammenführen
    all_events = incident_data + login_data + logout_data + config_data

    # Nur gewünschte Felder behalten
    fields_to_keep = ['timestamp', 'event_type', 'reason','ip_address', 'action','result', 'severity']
    filtered_events = filter_fields(all_events, fields_to_keep)

    # Sortieren von neu nach alt
    sorted_events = sorted(
        filtered_events,
        key=lambda x: x.get('timestamp') or '0000-00-00T00:00:00',
        reverse=True
    )

    return Response(sorted_events)
def filter_fields(data, fields_to_keep):
    """
    Filtert die Liste der Daten, sodass nur die angegebenen Felder beibehalten werden.
    """
    return [{k: item[k] for k in fields_to_keep if k in item} for item in data]

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
