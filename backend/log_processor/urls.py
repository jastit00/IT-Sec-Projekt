from django.urls import path
from log_processor.views.upload import LogFileUploadView
from log_processor.views.config import IncidentConfigAPIView
from log_processor.views.analytics import processed_logins, processed_config_changes, dos_packets, ddos_packets
from log_processor.views.unified_log import unified_event_log

urlpatterns = [
    path('logfiles/', LogFileUploadView.as_view(), name='upload-log-file'),
    path('incidents-config/', IncidentConfigAPIView.as_view(), name='incidents-config'),
    path('logfiles/processed-logins/', processed_logins, name='processed-logins'),
    path('logfiles/config-changes/', processed_config_changes, name='processed-config-changes'),
    path('logfiles/unified-event-log/', unified_event_log, name='unified-event-log'),
    path('logfiles/dos-packets/', dos_packets, name='dos-packets'),
    path('logfiles/ddos-packets/', ddos_packets, name='ddos-packets'),
]

