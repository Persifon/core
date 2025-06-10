from django.urls import path
import views

urlpatterns = [
    path('generate_payload/', views.generate_payload, name='generate_payload'),
    path('verify/', views.verify_signature, name='verify_signature'),
]