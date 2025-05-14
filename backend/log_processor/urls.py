from django.urls import path
from . import views

urlpatterns = [
    path('logfiles/', views.LogFileUploadView.as_view(), name='upload-log-file'),
    path('logfiles/processed-logins/', views.processed_logins, name='processed-logins'),
    path('logfiles/config_changes/', views.processed_config_changes, name='processed-config-changes'),
    path('logfiles/incidents/', views.processed_incidents, name='processed-incidents'),
    path('logfiles/unified_event_log/', views.unified_event_log, name='unified_event_log'),

]

