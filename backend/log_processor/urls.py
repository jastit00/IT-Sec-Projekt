from django.urls import path
from . import views

urlpatterns = [
    path('logfiles/', views.LogFileUploadView.as_view(), name='upload-log-file'),
    path('logfiles/processed-logins/', views.processed_logins, name='processed-logins'),
    path('logfiles/config-changes/', views.processed_config_changes, name='processed-config-changes'),
    path('logfiles/incidents/', views.processed_incidents, name='processed-incidents'),
    path('logfiles/unified-event-log/', views.unified_event_log, name='unified-event-log'),
    path('logfiles/dos-packets/', views.dos_packets, name='dos-packets'),
    path('logfiles/ddos-packets/', views.ddos_packets, name='ddos-packets'),
]

