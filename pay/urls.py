"""
URL configuration for pay project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from main.auth_views import (
    SecureTokenObtainPairView,
    SecureTokenRefreshView,
    SecureTokenVerifyView,
    LogoutView
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('blog/', include('blog.urls')),
    path('', include('main.urls')),
    path('api/token/', SecureTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', SecureTokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', SecureTokenVerifyView.as_view(), name='token_verify'),
    path('api/logout/', LogoutView.as_view(), name='logout'),
]
