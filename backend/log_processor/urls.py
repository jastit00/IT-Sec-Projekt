from django.urls import path
from . import views

urlpatterns = [
    path('upload-log/', views.upload_log_file),
]