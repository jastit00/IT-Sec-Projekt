from django.urls import path
from . import views

urlpatterns = [
    path('process_log/', views.process_log, name='process_log'),
]