"""
Enhanced authentication views with security features for PersifonPay.
"""

from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from django.utils import timezone

from .throttling import AuthenticationThrottle
from .security import AccountLockout, SecurityMonitor
from .audit import AuditLogger
from .validators import InputValidator


class SecureTokenObtainPairView(TokenObtainPairView):
    """
    Enhanced token obtain view with security features.
    """
    throttle_classes = [AuthenticationThrottle]
    
    def post(self, request, *args, **kwargs):
        """
        Authenticate user with security monitoring.
        """
        try:
            # Validate input
            username = request.data.get('username', '').strip()
            password = request.data.get('password', '')
            
            if not username or not password:
                AuditLogger.log_failed_attempt(
                    action='LOGIN',
                    description='Login attempt with missing credentials',
                    request=request,
                    error_message='Username and password are required'
                )
                return Response(
                    {'error': 'Username and password are required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check for account lockout
            if AccountLockout.is_locked_out(username, 'login'):
                lockout_info = AccountLockout.get_lockout_info(username, 'login')
                AuditLogger.log_failed_attempt(
                    action='LOGIN',
                    description=f'Login attempt for locked account: {username}',
                    request=request,
                    error_message='Account temporarily locked',
                    metadata={'lockout_info': lockout_info}
                )
                return Response(
                    {
                        'error': 'Account temporarily locked due to multiple failed attempts',
                        'time_remaining_seconds': lockout_info.get('time_remaining_seconds', 0)
                    },
                    status=status.HTTP_423_LOCKED
                )
            
            # Attempt authentication
            user = authenticate(username=username, password=password)
            
            if user is None:
                # Record failed attempt
                AccountLockout.record_failed_attempt(username, request, 'login')
                
                # Log failed attempt
                AuditLogger.log_authentication(
                    user=None,
                    action='LOGIN',
                    request=request,
                    success=False,
                    error_message='Invalid credentials'
                )
                
                # Get updated lockout info
                lockout_info = AccountLockout.get_lockout_info(username, 'login')
                response_data = {'error': 'Invalid credentials'}
                
                if lockout_info['attempts_remaining'] <= 2:
                    response_data['warning'] = f"Account will be locked after {lockout_info['attempts_remaining']} more failed attempts"
                
                return Response(response_data, status=status.HTTP_401_UNAUTHORIZED)
            
            # Check if user account is active
            if not user.is_active:
                AuditLogger.log_authentication(
                    user=user,
                    action='LOGIN',
                    request=request,
                    success=False,
                    error_message='Account is disabled'
                )
                return Response(
                    {'error': 'Account is disabled'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Successful authentication - clear failed attempts
            AccountLockout.clear_failed_attempts(username, 'login')
            
            # Generate tokens using the parent class
            serializer = self.get_serializer(data=request.data)
            
            try:
                serializer.is_valid(raise_exception=True)
            except Exception:
                AuditLogger.log_authentication(
                    user=user,
                    action='LOGIN',
                    request=request,
                    success=False,
                    error_message='Token generation failed'
                )
                return Response(
                    {'error': 'Authentication failed'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            # Log successful authentication
            AuditLogger.log_authentication(
                user=user,
                action='LOGIN',
                request=request,
                success=True
            )
            
            # Monitor for suspicious activity
            SecurityMonitor.monitor_suspicious_activity(
                user=user,
                action='LOGIN',
                request=request
            )
            
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            AuditLogger.log_failed_attempt(
                action='LOGIN',
                description='Login system error',
                request=request,
                error_message=str(e)
            )
            return Response(
                {'error': 'Authentication system error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SecureTokenRefreshView(TokenRefreshView):
    """
    Enhanced token refresh view with security features.
    """
    throttle_classes = [AuthenticationThrottle]
    
    def post(self, request, *args, **kwargs):
        """
        Refresh token with security monitoring.
        """
        try:
            # Get user from refresh token if possible
            user = None
            refresh_token = request.data.get('refresh')
            
            if refresh_token:
                try:
                    from rest_framework_simplejwt.tokens import RefreshToken
                    token_obj = RefreshToken(refresh_token)
                    from django.contrib.auth import get_user_model
                    User = get_user_model()
                    user = User.objects.get(id=token_obj['user_id'])
                except Exception:
                    pass  # Will be handled by parent class
            
            # Call parent implementation
            response = super().post(request, *args, **kwargs)
            
            if response.status_code == 200:
                # Log successful token refresh
                AuditLogger.log_authentication(
                    user=user,
                    action='TOKEN_REFRESH',
                    request=request,
                    success=True
                )
                
                # Monitor for suspicious activity
                if user:
                    SecurityMonitor.monitor_suspicious_activity(
                        user=user,
                        action='TOKEN_REFRESH',
                        request=request
                    )
            else:
                # Log failed token refresh
                AuditLogger.log_authentication(
                    user=user,
                    action='TOKEN_REFRESH',
                    request=request,
                    success=False,
                    error_message='Invalid refresh token'
                )
            
            return response
            
        except Exception as e:
            AuditLogger.log_failed_attempt(
                action='TOKEN_REFRESH',
                description='Token refresh system error',
                request=request,
                error_message=str(e)
            )
            return Response(
                {'error': 'Token refresh system error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SecureTokenVerifyView(TokenVerifyView):
    """
    Enhanced token verify view with audit logging.
    """
    
    def post(self, request, *args, **kwargs):
        """
        Verify token with audit logging.
        """
        response = super().post(request, *args, **kwargs)
        
        # We don't need extensive logging for token verification
        # as it happens frequently, but we can track failed verifications
        if response.status_code != 200:
            AuditLogger.log_security_event(
                user=None,
                action='TOKEN_VERIFY_FAILED',
                description='Token verification failed',
                request=request,
                severity='LOW'
            )
        
        return response


class LogoutView(APIView):
    """
    Logout view that blacklists the refresh token.
    """
    throttle_classes = [AuthenticationThrottle]
    
    def post(self, request):
        """
        Logout user by blacklisting refresh token.
        """
        try:
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response(
                    {'error': 'Refresh token is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Blacklist the refresh token
            from rest_framework_simplejwt.tokens import RefreshToken
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            # Log successful logout
            user = getattr(request, 'user', None)
            AuditLogger.log_authentication(
                user=user if user and user.is_authenticated else None,
                action='LOGOUT',
                request=request,
                success=True
            )
            
            return Response(
                {'message': 'Successfully logged out'},
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            AuditLogger.log_failed_attempt(
                action='LOGOUT',
                description='Logout system error',
                request=request,
                error_message=str(e)
            )
            return Response(
                {'error': 'Logout failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
