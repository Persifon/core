# urls.py
from django.urls import path
from main import views

urlpatterns = [
    path('api/applewallet/', views.create_profile),

]
