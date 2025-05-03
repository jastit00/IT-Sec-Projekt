from django.urls import path
from . import views

urlpatterns = [
    path('logfiles/', views.LogFileUploadView.as_view(), name='upload-log-file'),
    path('audit_logs/', views.processed_logins, name='processed-logins'),
    path('config_changes/', views.processed_config_changes, name='processed-config-changes'),
    path('incidents/', views.processed_incidents, name='processed-incidents'),
]
