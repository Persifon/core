import json
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.http import HttpRequest
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate

class DebugTokenView(APIView):
    """
    A debug view to check authentication and token generation.
    This will help troubleshoot authentication issues.
    """
    
    def post(self, request: HttpRequest):
        try:
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')
            
            if not username or not password:
                return Response({
                    'error': 'Username and password are required',
                    'provided': {
                        'username': bool(username),
                        'password': bool(password)
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Attempt to authenticate the user
            user = authenticate(username=username, password=password)
            
            if not user:
                return Response({
                    'error': 'Authentication failed',
                    'reason': 'Invalid credentials or user does not exist',
                    'username_provided': username
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            # Check if the user is active
            if not user.is_active:
                return Response({
                    'error': 'Authentication failed',
                    'reason': 'User account is inactive',
                    'username': username
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            # Generate token
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'user_info': {
                    'id': str(user.id),
                    'username': user.username,
                    'is_active': user.is_active,
                    'has_first_name': bool(user.first_name),
                    'has_family_name': bool(user.family_name),
                    'has_last_name': bool(user.last_name)
                },
                'tokens': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }
            }, status=status.HTTP_200_OK)
            
        except json.JSONDecodeError:
            return Response({'error': 'Invalid JSON data'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
