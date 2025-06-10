"""
Account lockout and security monitoring system for PersifonPay.
"""

import hashlib
from datetime import timedelta
from django.core.cache import cache
from django.utils import timezone
from .audit import AuditLogger


class AccountLockout:
    """
    Manages account lockout functionality to prevent brute force attacks.
    """
    
    # Configuration
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 30
    ATTEMPT_WINDOW_MINUTES = 15
    
    @staticmethod
    def get_attempt_key(identifier, attempt_type='login'):
        """
        Generate cache key for tracking attempts.
        """
        # Hash the identifier for privacy
        hashed = hashlib.sha256(f"{identifier}:{attempt_type}".encode()).hexdigest()
        return f"auth_attempts:{hashed}"
    
    @staticmethod
    def get_lockout_key(identifier, attempt_type='login'):
        """
        Generate cache key for lockout status.
        """
        hashed = hashlib.sha256(f"{identifier}:{attempt_type}".encode()).hexdigest()
        return f"auth_lockout:{hashed}"
    
    @staticmethod
    def record_failed_attempt(identifier, request=None, attempt_type='login'):
        """
        Record a failed login attempt and check if lockout should be triggered.
        """
        attempt_key = AccountLockout.get_attempt_key(identifier, attempt_type)
        lockout_key = AccountLockout.get_lockout_key(identifier, attempt_type)
        
        # Check if already locked out
        if cache.get(lockout_key):
            return True  # Already locked out
        
        # Get current attempts
        attempts = cache.get(attempt_key, [])
        now = timezone.now()
        
        # Remove attempts outside the window
        attempts = [
            attempt_time for attempt_time in attempts
            if now - attempt_time <= timedelta(minutes=AccountLockout.ATTEMPT_WINDOW_MINUTES)
        ]
        
        # Add current attempt
        attempts.append(now)
        
        # Update cache
        cache.set(
            attempt_key, 
            attempts, 
            timeout=AccountLockout.ATTEMPT_WINDOW_MINUTES * 60
        )
        
        # Check if lockout threshold reached
        if len(attempts) >= AccountLockout.MAX_LOGIN_ATTEMPTS:
            cache.set(
                lockout_key, 
                now, 
                timeout=AccountLockout.LOCKOUT_DURATION_MINUTES * 60
            )
            
            # Log security event
            AuditLogger.log_security_event(
                user=None,
                action='LOCKOUT',
                description=f"Account locked due to {len(attempts)} failed {attempt_type} attempts",
                request=request,
                severity='HIGH',
                metadata={
                    'identifier': identifier,
                    'attempt_type': attempt_type,
                    'attempts_count': len(attempts)
                }
            )
            
            return True  # Locked out
        
        return False  # Not locked out yet
    
    @staticmethod
    def is_locked_out(identifier, attempt_type='login'):
        """
        Check if an identifier is currently locked out.
        """
        lockout_key = AccountLockout.get_lockout_key(identifier, attempt_type)
        lockout_time = cache.get(lockout_key)
        
        if not lockout_time:
            return False
        
        # Check if lockout has expired
        if timezone.now() - lockout_time >= timedelta(minutes=AccountLockout.LOCKOUT_DURATION_MINUTES):
            cache.delete(lockout_key)
            return False
        
        return True
    
    @staticmethod
    def clear_failed_attempts(identifier, attempt_type='login'):
        """
        Clear failed attempts for successful authentication.
        """
        attempt_key = AccountLockout.get_attempt_key(identifier, attempt_type)
        cache.delete(attempt_key)
    
    @staticmethod
    def get_lockout_info(identifier, attempt_type='login'):
        """
        Get information about current lockout status.
        """
        lockout_key = AccountLockout.get_lockout_key(identifier, attempt_type)
        attempt_key = AccountLockout.get_attempt_key(identifier, attempt_type)
        
        lockout_time = cache.get(lockout_key)
        attempts = cache.get(attempt_key, [])
        
        if lockout_time:
            time_remaining = timedelta(minutes=AccountLockout.LOCKOUT_DURATION_MINUTES) - (timezone.now() - lockout_time)
            return {
                'locked_out': True,
                'time_remaining_seconds': max(0, int(time_remaining.total_seconds())),
                'attempts_count': len(attempts)
            }
        
        # Filter recent attempts
        now = timezone.now()
        recent_attempts = [
            attempt_time for attempt_time in attempts
            if now - attempt_time <= timedelta(minutes=AccountLockout.ATTEMPT_WINDOW_MINUTES)
        ]
        
        return {
            'locked_out': False,
            'attempts_count': len(recent_attempts),
            'attempts_remaining': AccountLockout.MAX_LOGIN_ATTEMPTS - len(recent_attempts)
        }


class SecurityMonitor:
    """
    Monitors and tracks security-related events.
    """
    
    @staticmethod
    def monitor_suspicious_activity(user, action, request=None, metadata=None):
        """
        Monitor and log potentially suspicious activities.
        """
        suspicious_indicators = []
        
        # Check for unusual IP addresses
        if request:
            ip = SecurityMonitor._get_client_ip(request)
            recent_ips_key = f"user_ips:{user.id}" if user else f"session_ips:{request.session.session_key}"
            recent_ips = cache.get(recent_ips_key, set())
            
            if ip not in recent_ips and len(recent_ips) > 0:
                suspicious_indicators.append("new_ip_address")
            
            recent_ips.add(ip)
            cache.set(recent_ips_key, recent_ips, timeout=86400)  # 24 hours
        
        # Check for rapid consecutive actions
        if user:
            action_key = f"user_actions:{user.id}:{action}"
            recent_actions = cache.get(action_key, [])
            now = timezone.now()
            
            # Remove old actions (older than 1 minute)
            recent_actions = [
                action_time for action_time in recent_actions
                if now - action_time <= timedelta(minutes=1)
            ]
            
            if len(recent_actions) > 10:  # More than 10 actions per minute
                suspicious_indicators.append("rapid_actions")
            
            recent_actions.append(now)
            cache.set(action_key, recent_actions, timeout=60)
        
        # Log if suspicious activity detected
        if suspicious_indicators:
            AuditLogger.log_security_event(
                user=user,
                action='SUSPICIOUS_ACTIVITY',
                description=f"Suspicious activity detected: {', '.join(suspicious_indicators)}",
                request=request,
                severity='HIGH',
                metadata={
                    'indicators': suspicious_indicators,
                    'original_action': action,
                    **(metadata or {})
                }
            )
    
    @staticmethod
    def _get_client_ip(request):
        """
        Extract client IP address from request.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')
