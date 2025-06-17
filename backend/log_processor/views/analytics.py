import logging

from log_processor.views.utils import get_filtered_queryset
from rest_framework.decorators import api_view
from rest_framework.response import Response


from incident_detector.models import (
    DDosIncident,
    DosIncident,
)
from incident_detector.serializers import (
    DDosIncidentSerializer,
    DosIncidentSerializer,
)


from log_processor.models import (
    UsysConfig,
    UserLogin,
)
from log_processor.serializers import (
    UsysConfigSerializer,
    UserLoginSerializer,
)


logger = logging.getLogger(__name__)

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

    data = get_filtered_queryset(
        model=UsysConfig,
        serializer_class=UsysConfigSerializer,
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