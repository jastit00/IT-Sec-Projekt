import logging

from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from incident_detector.models import (
    DosIncident, DDosIncident, ConfigIncident,
    ConcurrentLoginIncident, BruteforceIncident
)
from incident_detector.serializers import (
    DosIncidentSerializer, DDosIncidentSerializer,
    ConfigIncidentSerializer, ConcurrentLoginIncidentSerializer,
    BruteforceIncidentSerializer
)
from log_processor.models import (
    UserLogin, UsysConfig, UserLogout, NetfilterPackets
)
from log_processor.serializers import (
    LogFileSerializer, UserLoginSerializer, UsysConfigSerializer,
    UserLogoutSerializer, NetfilterPacketsSerializer
)
from log_processor.services import handle_uploaded_log_file


logger = logging.getLogger(__name__)#für den ligger name falls was schief geht einfacher einsehbar wo





class LogFileUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, *args, **kwargs):
        uploaded_file = request.FILES.get('file')
        source = request.data.get('source', 'unknown')
        uploaded_by_user = request.data.get('uploaded_by_user', 'anonym')

        if not uploaded_file:
            logger.warning("Upload attempt without file.")
            return Response({"status": "error", "message": "Please upload a file"}, status=status.HTTP_400_BAD_REQUEST)

        if not uploaded_file.name.endswith('.log'):
            logger.warning("Upload attempt with invalid file type.")
            return Response({"status": "error", "message": "Only .log files are allowed."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            result = handle_uploaded_log_file(uploaded_file, source, uploaded_by_user)
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





@api_view(['GET'])
def processed_logins(request):
    start = request.query_params.get('start')
    end = request.query_params.get('end')
    data = get_filtered_queryset(
        model=UserLogin,
        serializer_class=UserLoginSerializer,
        start=start,
        end=end
    )
    return Response(data)


@api_view(['GET'])
def processed_config_changes(request):
    start = request.query_params.get('start')
    end = request.query_params.get('end')
    fields_to_keep = ['timestamp', 'action','terminal', 'result', 'event_type', 'severity']
    data = get_filtered_queryset(
        model=UsysConfig,
        serializer_class=UsysConfigSerializer,
        fields_to_keep=fields_to_keep,
        start=start,
        end=end
    )
    return Response(data)




@api_view(['GET'])
def ddos_packets(request):
    start = request.query_params.get('start')
    end = request.query_params.get('end')

    fields_to_keep = ['timestamp', 'dst_ip_address', 'protocol', 'packets', 'timeDelta', 'sources']

    data = get_filtered_queryset(
        model=DDosIncident,
        serializer_class=DDosIncidentSerializer,
        fields_to_keep=fields_to_keep,
        start=start,
        end=end
    )
    return Response(data)




@api_view(['GET'])
def dos_packets(request):
    start = request.query_params.get('start')
    end = request.query_params.get('end')

    fields_to_keep = ['timestamp', 'dst_ip_address', 'protocol', 'packets', 'timeDelta', 'src_ip_address']

    data = get_filtered_queryset(
        model=DosIncident,
        serializer_class=DosIncidentSerializer,
        fields_to_keep=fields_to_keep,
        start=start,
        end=end
    )
    return Response(data)



@csrf_exempt
@api_view(['GET'])
def unified_event_log(request):
    models_and_serializers = [
        (UserLogin, UserLoginSerializer),
        (UserLogout, UserLogoutSerializer),
        (UsysConfig, UsysConfigSerializer),
        (NetfilterPackets, NetfilterPacketsSerializer),
        (DDosIncident, DDosIncidentSerializer),
        (DosIncident, DosIncidentSerializer),
        (ConfigIncident, ConfigIncidentSerializer),
        (ConcurrentLoginIncident, ConcurrentLoginIncidentSerializer),
        (BruteforceIncident, BruteforceIncidentSerializer),
    ]

    all_events = []
    for model, serializer in models_and_serializers:
        queryset = model.objects.all() 
        serialized = serializer(queryset, many=True).data
        all_events.extend(serialized)

    fields_to_keep = [
        'timestamp', 'event_type', 'reason', 'src_ip_address', 'dst_ip_address',
        'action', 'result', 'severity', 'packet_input', 'incident_type', 'protocol', 'count'
    ]

    filtered_events = filter_fields(all_events, fields_to_keep)
    sorted_events = sorted(
        filtered_events,
        key=lambda x: x.get('timestamp') or '0000-00-00T00:00:00',
        reverse=True
    )
    return Response(sorted_events)




def filter_fields(data, fields_to_keep):
    return [{k: item[k] for k in fields_to_keep if k in item} for item in data]



def get_filtered_queryset(model, serializer_class, start=None, end=None, fields_to_keep=None):
    queryset = model.objects.all()
    if start:
        queryset = queryset.filter(timestamp__gte=start)
    if end:
        queryset = queryset.filter(timestamp__lte=end)

    queryset = queryset.order_by('-timestamp')

    serializer = serializer_class(queryset, many=True)
    data = serializer.data

    if fields_to_keep:
        return filter_fields(data, fields_to_keep)

    return data
