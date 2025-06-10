"""
Two-Factor Authentication (2FA) API views for PersifonPay.
Provides secure endpoints for 2FA setup, verification, and management.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.db import transaction
from django.contrib.auth import get_user_model

from .two_factor import TwoFactorAuth, TwoFactorAuthMixin
from .audit import AuditLogger
from .security import SecurityMonitor
from .throttling import TwoFactorThrottle
from .validators import InputValidator
from .utils import get_client_ip

User = get_user_model()


class TwoFactorSetupView(APIView, TwoFactorAuthMixin):
    """
    API view for initiating 2FA setup.
    Generates secret and QR code for user to configure authenticator app.
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [TwoFactorThrottle]
    
    def __init__(self):
        super().__init__()
        self.two_factor_auth = TwoFactorAuth()
        self.audit_logger = AuditLogger()
        self.security_monitor = SecurityMonitor()
        self.validator = InputValidator()
    
    def post(self, request):
        import sys
        print('DEBUG 2FA: request.user =', request.user, 'is_authenticated =', getattr(request.user, 'is_authenticated', None), 'request.auth =', getattr(request, 'auth', None), file=sys.stderr)
        """
        Generate 2FA setup data (secret and QR code).
        
        Returns:
            - secret: Base32 secret for manual entry
            - qr_code: Base64 encoded QR code image
            - backup_codes: List of recovery codes
        """
        user = request.user
        client_ip = get_client_ip(request)
        
        try:
            # Check if 2FA is already enabled
            if user.two_factor_enabled:
                self.audit_logger.log_security_event(
                    user=user,
                    action='2FA_SETUP_ATTEMPT_WHEN_ENABLED',
                    description='User attempted to setup 2FA when already enabled',
                    severity='WARNING',
                    metadata={'ip_address': client_ip}
                )
                return Response({
                    'data': None,
                    'error': 'Two-factor authentication is already enabled'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            with transaction.atomic():
                # Generate new secret
                secret = self.two_factor_auth.generate_secret()
                
                # Generate QR code
                qr_code = self.two_factor_auth.generate_qr_code(user, secret)
                
                # Generate backup codes
                backup_codes = self.two_factor_auth.generate_backup_codes()
                hashed_codes = self.two_factor_auth.hash_backup_codes(backup_codes)
                
                # Store setup data temporarily (not enabled yet)
                user.two_factor_secret = secret
                user.backup_codes = hashed_codes
                user.two_factor_setup_date = timezone.now()
                user.save(update_fields=[
                    'two_factor_secret', 
                    'backup_codes', 
                    'two_factor_setup_date'
                ])
                
                # Log successful setup initiation
                self.audit_logger.log_security_event(
                    user=user,
                    action='2FA_SETUP_INITIATED',
                    description=f'2FA setup initiated at {user.two_factor_setup_date.isoformat()}',
                    severity='INFO',
                    metadata={'ip_address': client_ip, 'setup_date': user.two_factor_setup_date.isoformat()}
                )
                
                return Response({
                    'message': '2FA setup initiated successfully',
                    'data': {
                        'secret': secret,
                        'qr_code': qr_code,
                        'backup_codes': backup_codes,
                        'setup_instructions': {
                            'step1': 'Install an authenticator app (Google Authenticator, Authy, etc.)',
                            'step2': 'Scan the QR code or enter the secret manually',
                            'step3': 'Save the backup codes in a secure location',
                            'step4': 'Verify setup with a token from your authenticator app'
                        }
                    }
                }, status=status.HTTP_200_OK)
                
        except (ValueError, RuntimeError, KeyError) as e:
            self.audit_logger.log_security_event(
                user=user,
                action='2FA_SETUP_ERROR',
                description=f'2FA setup error: {str(e)}',
                severity='ERROR',
                metadata={'ip_address': client_ip, 'error': str(e)}
            )
            return Response({
                'data': None,
                'error': 'Failed to setup two-factor authentication'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TwoFactorVerifySetupView(APIView, TwoFactorAuthMixin):
    """
    API view for verifying and completing 2FA setup.
    User must provide a valid TOTP token to enable 2FA.
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [TwoFactorThrottle]
    
    def __init__(self):
        super().__init__()
        self.two_factor_auth = TwoFactorAuth()
        self.audit_logger = AuditLogger()
        self.security_monitor = SecurityMonitor()
        self.validator = InputValidator()
    
    def post(self, request):
        """
        Verify TOTP token and enable 2FA.
        
        Request body:
            - token: 6-digit TOTP token from authenticator app
        """
        user = request.user
        client_ip = get_client_ip(request)
        
        try:
            # Validate input
            token = request.data.get('token', '').strip()
            if not self.validator.validate_totp_token(token):
                return Response({
                    'data': None,
                    'error': 'Invalid token format. Please provide a 6-digit code.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if 2FA is already enabled
            if user.two_factor_enabled:
                return Response({
                    'data': None,
                    'error': 'Two-factor authentication is already enabled'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if setup was initiated
            if not user.two_factor_secret:
                return Response({
                    'data': None,
                    'error': 'Two-factor authentication setup not initiated'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Verify the token
            if not self.two_factor_auth.verify_totp(user.two_factor_secret, token):
                self.audit_logger.log_security_event(
                    user=user,
                    action='2FA_SETUP_VERIFICATION_FAILED',
                    description='Invalid verification code during 2FA setup',
                    severity='WARNING',
                    metadata={'ip_address': client_ip, 'token_provided': len(token) == 6}
                )
                return Response({
                    'data': None,
                    'error': 'Invalid verification code'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            with transaction.atomic():
                # Enable 2FA
                user.two_factor_enabled = True
                user.two_factor_enabled_date = timezone.now()
                user.last_totp_used = token  # Prevent immediate reuse
                user.save(update_fields=[
                    'two_factor_enabled',
                    'two_factor_enabled_date',
                    'last_totp_used'
                ])
                
                # Log successful 2FA enablement
                self.audit_logger.log_security_event(
                    user=user,
                    action='2FA_ENABLED',
                    description=f'2FA enabled at {user.two_factor_enabled_date.isoformat()}',
                    severity='INFO',
                    metadata={'ip_address': client_ip, 'enabled_date': user.two_factor_enabled_date.isoformat(), 'backup_codes_count': len(user.backup_codes) if user.backup_codes else 0}
                )
                
                return Response({
                    'message': 'Two-factor authentication enabled successfully',
                    'data': {
                        'enabled': True,
                        'enabled_date': user.two_factor_enabled_date.isoformat(),
                        'backup_codes_remaining': len(user.backup_codes) if user.backup_codes else 0
                    }
                }, status=status.HTTP_200_OK)
        except (ValueError, RuntimeError, KeyError) as e:
            self.audit_logger.log_security_event(
                user=user,
                action='2FA_SETUP_VERIFICATION_ERROR',
                description=f'2FA setup verification error: {str(e)}',
                severity='ERROR',
                metadata={'ip_address': client_ip, 'error': str(e)}
            )
            return Response({
                'data': None,
                'error': 'Failed to verify two-factor authentication setup'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TwoFactorDisableView(APIView, TwoFactorAuthMixin):
    """
    API view for disabling 2FA.
    Requires current password and 2FA token for security.
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [TwoFactorThrottle]
    
    def __init__(self):
        super().__init__()
        self.two_factor_auth = TwoFactorAuth()
        self.audit_logger = AuditLogger()
        self.security_monitor = SecurityMonitor()
        self.validator = InputValidator()
    
    def post(self, request):
        """
        Disable 2FA after verification.
        
        Request body:
            - password: Current account password
            - token: Current 2FA token or backup code
        """
        user = request.user
        client_ip = get_client_ip(request)
        
        try:
            # Validate input
            password = request.data.get('password', '')
            token = request.data.get('token', '').strip()
            if not password:
                return Response({
                    'data': None,
                    'error': 'Password is required'
                }, status=status.HTTP_400_BAD_REQUEST)
            if not token:
                return Response({
                    'data': None,
                    'error': '2FA token is required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if 2FA is enabled
            if not user.two_factor_enabled:
                return Response({
                    'data': None,
                    'error': 'Two-factor authentication is not enabled'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Verify password
            if not user.check_password(password):
                self.audit_logger.log_security_event(
                    user=user,
                    action='2FA_DISABLE_INVALID_PASSWORD',
                    description='Invalid password during 2FA disable',
                    severity='WARNING',
                    metadata={'ip_address': client_ip, 'attempt_time': timezone.now().isoformat()}
                )
                return Response({
                    'data': None,
                    'error': 'Invalid password'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            # Verify 2FA token
            is_valid, token_type = self.verify_2fa_token(user, token)
            if not is_valid:
                self.audit_logger.log_security_event(
                    user=user,
                    action='2FA_DISABLE_INVALID_TOKEN',
                    description='Invalid 2FA token during disable',
                    severity='WARNING',
                    metadata={'ip_address': client_ip, 'token_type': token_type}
                )
                return Response({
                    'data': None,
                    'error': 'Invalid 2FA token'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            with transaction.atomic():
                # Disable 2FA and clear related data
                user.two_factor_enabled = False
                user.two_factor_secret = ''
                user.backup_codes = []
                user.last_totp_used = ''
                user.two_factor_disabled_date = timezone.now()
                user.save(update_fields=[
                    'two_factor_enabled',
                    'two_factor_secret',
                    'backup_codes',
                    'last_totp_used',
                    'two_factor_disabled_date'
                ])
                
                # Log 2FA disabling
                self.audit_logger.log_security_event(
                    user=user,
                    action='2FA_DISABLED',
                    description=f'2FA disabled at {user.two_factor_disabled_date.isoformat()}',
                    severity='WARNING',
                    metadata={'ip_address': client_ip, 'disabled_date': user.two_factor_disabled_date.isoformat(), 'token_type_used': token_type}
                )
                
                return Response({
                    'message': 'Two-factor authentication disabled successfully',
                    'data': {
                        'enabled': False,
                        'disabled_date': user.two_factor_disabled_date.isoformat()
                    }
                }, status=status.HTTP_200_OK)
        except (ValueError, RuntimeError, KeyError) as e:
            self.audit_logger.log_security_event(
                user=user,
                action='2FA_DISABLE_ERROR',
                description=f'2FA disable error: {str(e)}',
                severity='ERROR',
                metadata={'ip_address': client_ip, 'error': str(e)}
            )
            return Response({
                'data': None,
                'error': 'Failed to disable two-factor authentication'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TwoFactorStatusView(APIView):
    """
    API view for checking 2FA status and settings.
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [TwoFactorThrottle]
    
    def get(self, request):
        """
        Get current 2FA status and settings.
        """
        user = request.user
        
        return Response({
            'data': {
                'enabled': user.two_factor_enabled,
                'setup_date': user.two_factor_setup_date.isoformat() if user.two_factor_setup_date else None,
                'enabled_date': user.two_factor_enabled_date.isoformat() if user.two_factor_enabled_date else None,
                'backup_codes_remaining': len(user.backup_codes) if user.backup_codes else 0,
                'requires_setup': not user.two_factor_enabled and not user.two_factor_secret
            }
        }, status=status.HTTP_200_OK)


class TwoFactorBackupCodesView(APIView, TwoFactorAuthMixin):
    """
    API view for managing backup codes.
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [TwoFactorThrottle]
    
    def __init__(self):
        super().__init__()
        self.two_factor_auth = TwoFactorAuth()
        self.audit_logger = AuditLogger()
        self.security_monitor = SecurityMonitor()
        self.validator = InputValidator()
    
    def post(self, request):
        """
        Generate new backup codes.
        
        Request body:
            - password: Current account password
            - token: Current 2FA token
        """
        user = request.user
        client_ip = get_client_ip(request)
        
        try:
            # Check if 2FA is enabled
            if not user.two_factor_enabled:
                return Response({
                    'error': 'Two-factor authentication is not enabled'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate input
            password = request.data.get('password', '')
            token = request.data.get('token', '').strip()
            
            if not password:
                return Response({
                    'error': 'Password is required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if not token:
                return Response({
                    'error': '2FA token is required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Verify password
            if not user.check_password(password):
                self.audit_logger.log_security_event(
                    user=user,
                    event_type='2FA_BACKUP_CODES_INVALID_PASSWORD',
                    severity='WARNING',
                    ip_address=client_ip
                )
                return Response({
                    'error': 'Invalid password'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            # Verify 2FA token
            is_valid, token_type = self.verify_2fa_token(user, token, allow_backup_code=False)
            if not is_valid:
                self.audit_logger.log_security_event(
                    user=user,
                    event_type='2FA_BACKUP_CODES_INVALID_TOKEN',
                    severity='WARNING',
                    ip_address=client_ip
                )
                return Response({
                    'error': 'Invalid 2FA token'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            with transaction.atomic():
                # Generate new backup codes
                backup_codes = self.two_factor_auth.generate_backup_codes()
                hashed_codes = self.two_factor_auth.hash_backup_codes(backup_codes)
                
                # Update user
                user.backup_codes = hashed_codes
                user.save(update_fields=['backup_codes'])
                
                # Log backup codes regeneration
                self.audit_logger.log_security_event(
                    user=user,
                    event_type='2FA_BACKUP_CODES_REGENERATED',
                    severity='INFO',
                    ip_address=client_ip,
                    details={'codes_count': len(backup_codes)}
                )
                
                return Response({
                    'message': 'New backup codes generated successfully',
                    'data': {
                        'backup_codes': backup_codes,
                        'warning': 'Save these codes in a secure location. They will not be shown again.'
                    }
                }, status=status.HTTP_200_OK)
                
        except Exception as e:
            self.audit_logger.log_security_event(
                user=user,
                event_type='2FA_BACKUP_CODES_ERROR',
                severity='ERROR',
                ip_address=client_ip,
                details={'error': str(e)}
            )
            return Response({
                'error': 'Failed to generate backup codes'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TwoFactorVerifyView(APIView, TwoFactorAuthMixin):
    """
    API view for standalone 2FA token verification.
    Used for sensitive operations that require 2FA confirmation.
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [TwoFactorThrottle]
    
    def __init__(self):
        super().__init__()
        self.two_factor_auth = TwoFactorAuth()
        self.audit_logger = AuditLogger()
        self.validator = InputValidator()
    
    def post(self, request):
        """
        Verify 2FA token for sensitive operations.
        
        Request body:
            - token: 2FA token or backup code
            - operation: Name of the operation being authorized (optional)
        """
        user = request.user
        client_ip = get_client_ip(request)
        
        try:
            # Validate input
            token = request.data.get('token', '').strip()
            operation = request.data.get('operation', 'verification')
            if not token:
                return Response({
                    'data': None,
                    'error': '2FA token is required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if 2FA is enabled
            if not user.two_factor_enabled:
                return Response({
                    'data': None,
                    'error': 'Two-factor authentication is not enabled'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Verify token
            is_valid, token_type = self.verify_2fa_token(user, token)
            if is_valid:
                self.audit_logger.log_security_event(
                    user=user,
                    action='2FA_VERIFICATION_SUCCESS',
                    description=f'2FA verification successful for operation: {operation}',
                    severity='INFO',
                    metadata={'ip_address': client_ip, 'operation': operation, 'token_type': token_type}
                )
                return Response({
                    'message': '2FA verification successful',
                    'data': {
                        'verified': True,
                        'token_type': token_type,
                        'operation': operation
                    }
                }, status=status.HTTP_200_OK)
            else:
                self.audit_logger.log_security_event(
                    user=user,
                    action='2FA_VERIFICATION_FAILED',
                    description=f'2FA verification failed for operation: {operation}',
                    severity='WARNING',
                    metadata={'ip_address': client_ip, 'operation': operation, 'failure_reason': token_type}
                )
                return Response({
                    'data': None,
                    'error': 'Invalid 2FA token',
                    'details': {
                        'reason': token_type,
                        'backup_codes_remaining': len(user.backup_codes) if user.backup_codes else 0
                    }
                }, status=status.HTTP_401_UNAUTHORIZED)
        except (ValueError, RuntimeError, KeyError) as e:
            self.audit_logger.log_security_event(
                user=user,
                action='2FA_VERIFICATION_ERROR',
                description=f'2FA verification error: {str(e)}',
                severity='ERROR',
                metadata={'ip_address': client_ip, 'error': str(e)}
            )
            return Response({
                'data': None,
                'error': 'Failed to verify 2FA token'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
