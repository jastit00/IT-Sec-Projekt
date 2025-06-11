import logging

from log_processor.views.helpers import filter_fields
from rest_framework.decorators import api_view
from rest_framework.response import Response


from incident_detector.models import (
    BruteforceIncident,
    ConfigIncident,
    ConcurrentLoginIncident,
    DDosIncident,
    DosIncident,
)
from incident_detector.serializers import (
    BruteforceIncidentSerializer,
    ConfigIncidentSerializer,
    ConcurrentLoginIncidentSerializer,
    DDosIncidentSerializer,
    DosIncidentSerializer,
)

from log_processor.models import (
    NetfilterPackets,
    UsysConfig,
    UserLogin,
    UserLogout,
)
from log_processor.serializers import (
    NetfilterPacketsSerializer,
    UsysConfigSerializer,
    UserLoginSerializer,
    UserLogoutSerializer,
)



logger = logging.getLogger(__name__)


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
        'action', 'result', 'severity', 'packet_input', 'incident_type', 'protocol', 'count','table',
    ]

    filtered_events = filter_fields(all_events, fields_to_keep)
    sorted_events = sorted(
        filtered_events,
        key=lambda x: x.get('timestamp') or '0000-00-00T00:00:00',
        reverse=True
    )
    return Response(sorted_events)