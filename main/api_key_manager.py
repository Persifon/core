"""
API Key management utilities for PersifonPay.
Provides functionality for generating, validating, and managing API keys.
"""

import secrets
import hashlib
import hmac
from typing import Optional, Tuple, List
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import models
from .models import APIKey, APIKeyUsage
from .audit import AuditLogger

User = get_user_model()


class APIKeyManager:
    """
    Handles API key generation, validation, and management.
    """
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.key_length = 32  # Length of the generated key
        self.prefix_length = 8  # Length of the key prefix for identification
    
    def generate_api_key(self, user, name: str, description: str = "", 
                        permissions: str = "READ", scopes: List[str] = None,
                        allowed_ips: List[str] = None, expires_at=None,
                        rate_limit: int = 1000) -> Tuple[str, APIKey]:
        """
        Generate a new API key for a user.
        
        Args:
            user: User instance
            name: Name for the API key
            description: Optional description
            permissions: Permission level ('READ', 'READ_WRITE', 'ADMIN')
            scopes: List of allowed scopes
            allowed_ips: List of allowed IP addresses
            expires_at: Optional expiration datetime
            rate_limit: Rate limit per hour (default: 1000)
            
        Returns:
            Tuple of (raw_key, api_key_instance)
        """
        # Generate raw API key
        raw_key = self._generate_raw_key()
        
        # Create key hash for storage
        key_hash = self._hash_key(raw_key)
        
        # Extract prefix for identification
        prefix = raw_key[:self.prefix_length]
        
        # Create API key instance
        api_key = APIKey.objects.create(
            name=name,
            description=description,
            key_hash=key_hash,
            prefix=prefix,
            created_by=user,
            permissions=permissions,
            scopes=scopes or [],
            allowed_ips=allowed_ips or [],
            expires_at=expires_at,
            rate_limit=rate_limit,
            status='ACTIVE'
        )
        
        # Log API key creation
        self.audit_logger.log_security_event(
            user=user,
            action='CREATE',
            description=f'API key created: {name}',
            metadata={
                'api_key_id': str(api_key.id),
                'api_key_name': name,
                'permissions': permissions,
                'scopes': scopes or [],
                'has_ip_restrictions': bool(allowed_ips),
                'has_expiration': bool(expires_at)
            }
        )
        
        return raw_key, api_key
    
    def validate_api_key(self, raw_key: str, ip_address: str = None, 
                        scope: str = None) -> Tuple[bool, Optional[APIKey], str]:
        """
        Validate an API key and check permissions.
        
        Args:
            raw_key: The raw API key to validate
            ip_address: Client IP address for IP restriction checking
            scope: Required scope for the operation
            
        Returns:
            Tuple of (is_valid, api_key_instance, error_message)
        """
        if not raw_key:
            return False, None, "API key is required"
        
        try:
            # Extract prefix for quick lookup
            prefix = raw_key[:self.prefix_length]
            
            # Find API key by prefix
            try:
                api_key = APIKey.objects.get(prefix=prefix)
            except APIKey.DoesNotExist:
                return False, None, "Invalid API key"
            
            # Verify key hash
            if not self._verify_key_hash(raw_key, api_key.key_hash):
                return False, None, "Invalid API key"
            
            # Check if key is valid (active and not expired)
            if not api_key.is_valid():
                return False, None, f"API key is {api_key.status.lower()}"
            
            # Check IP restrictions
            if ip_address and not api_key.is_ip_allowed(ip_address):
                self.audit_logger.log_security_event(
                    user=api_key.created_by,
                    action='VIEW',
                    description=f'API key IP violation from {ip_address}',
                    severity='WARNING',
                    metadata={
                        'api_key_id': str(api_key.id),
                        'blocked_ip': ip_address,
                        'allowed_ips': api_key.allowed_ips
                    }
                )
                return False, None, "IP address not allowed"
            
            # Check scope permissions
            if scope and not api_key.has_scope(scope):
                return False, None, f"Insufficient permissions for scope: {scope}"
            
            # Update usage tracking
            api_key.increment_usage()
            
            return True, api_key, ""
            
        except Exception as e:
            return False, None, f"API key validation error: {str(e)}"
    
    def revoke_api_key(self, api_key_id: str, user, reason: str = "") -> bool:
        """
        Revoke an API key.
        
        Args:
            api_key_id: UUID of the API key to revoke
            user: User performing the revocation
            reason: Optional reason for revocation
            
        Returns:
            bool: True if successfully revoked, False otherwise
        """
        try:
            api_key = APIKey.objects.get(id=api_key_id, created_by=user)
            api_key.status = 'REVOKED'
            api_key.save(update_fields=['status'])
            
            # Log revocation
            self.audit_logger.log_security_event(
                user=user,
                action='DELETE',
                description=f'API key revoked: {api_key.name}',
                severity='WARNING',
                metadata={
                    'api_key_id': str(api_key.id),
                    'api_key_name': api_key.name,
                    'reason': reason
                }
            )
            
            return True
            
        except APIKey.DoesNotExist:
            return False
    
    def list_user_keys(self, user, include_revoked: bool = False) -> List[APIKey]:
        """
        List all API keys for a user.
        
        Args:
            user: User instance
            include_revoked: Whether to include revoked keys
            
        Returns:
            List of APIKey instances
        """
        queryset = APIKey.objects.filter(created_by=user)
        
        if not include_revoked:
            queryset = queryset.exclude(status='REVOKED')
        
        return queryset.order_by('-created_at')
    
    def get_usage_stats(self, api_key: APIKey, days: int = 30) -> dict:
        """
        Get usage statistics for an API key.
        
        Args:
            api_key: APIKey instance
            days: Number of days to look back (default: 30)
            
        Returns:
            Dictionary with usage statistics
        """
        since_date = timezone.now() - timezone.timedelta(days=days)
        
        usage_logs = APIKeyUsage.objects.filter(
            api_key=api_key,
            timestamp__gte=since_date
        )
        
        total_requests = usage_logs.count()
        successful_requests = usage_logs.filter(status_code__lt=400).count()
        error_requests = total_requests - successful_requests
        
        # Get average response time
        avg_response_time = usage_logs.filter(
            response_time_ms__isnull=False
        ).aggregate(
            avg_time=models.Avg('response_time_ms')
        )['avg_time'] or 0
        
        # Get most frequent endpoints
        popular_endpoints = usage_logs.values('path').annotate(
            count=models.Count('path')
        ).order_by('-count')[:5]
        
        return {
            'total_requests': total_requests,
            'successful_requests': successful_requests,
            'error_requests': error_requests,
            'success_rate': (successful_requests / total_requests * 100) if total_requests > 0 else 0,
            'avg_response_time_ms': round(avg_response_time, 2),
            'popular_endpoints': list(popular_endpoints),
            'last_used': api_key.last_used,
            'days_analyzed': days
        }
    
    def check_rate_limit(self, api_key: APIKey, window_hours: int = 1) -> Tuple[bool, int, int]:
        """
        Check if API key is within rate limits.
        
        Args:
            api_key: APIKey instance
            window_hours: Time window in hours (default: 1)
            
        Returns:
            Tuple of (within_limit, current_usage, rate_limit)
        """
        since_time = timezone.now() - timezone.timedelta(hours=window_hours)
        
        current_usage = APIKeyUsage.objects.filter(
            api_key=api_key,
            timestamp__gte=since_time
        ).count()
        
        rate_limit = api_key.rate_limit
        within_limit = current_usage < rate_limit
        
        return within_limit, current_usage, rate_limit
    
    def log_api_usage(self, api_key: APIKey, request, response, 
                     response_time_ms: int = None) -> APIKeyUsage:
        """
        Log API key usage for analytics and rate limiting.
        
        Args:
            api_key: APIKey instance
            request: Django request object
            response: Django response object
            response_time_ms: Response time in milliseconds
            
        Returns:
            APIKeyUsage instance
        """
        from .utils import get_client_ip
        
        usage_log = APIKeyUsage.objects.create(
            api_key=api_key,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            method=request.method,
            path=request.path,
            status_code=response.status_code,
            response_time_ms=response_time_ms,
            request_size=len(request.body) if hasattr(request, 'body') else None,
            response_size=len(response.content) if hasattr(response, 'content') else None,
            error_message=getattr(response, 'error_message', '')
        )
        
        return usage_log
    
    def _generate_raw_key(self) -> str:
        """Generate a raw API key using secure random generation."""
        return secrets.token_urlsafe(self.key_length)
    
    def _hash_key(self, raw_key: str) -> str:
        """Create a secure hash of the API key for storage."""
        return hashlib.sha256(raw_key.encode()).hexdigest()
    
    def _verify_key_hash(self, raw_key: str, stored_hash: str) -> bool:
        """Verify a raw key against a stored hash using secure comparison."""
        computed_hash = self._hash_key(raw_key)
        return hmac.compare_digest(computed_hash, stored_hash)


class APIKeyScopes:
    """
    Define available API scopes for granular permission control.
    """
    
    # Account scopes
    ACCOUNTS_READ = "accounts:read"
    ACCOUNTS_WRITE = "accounts:write"
    ACCOUNTS_DELETE = "accounts:delete"
    
    # Transaction scopes
    TRANSACTIONS_READ = "transactions:read"
    TRANSACTIONS_WRITE = "transactions:write"
    
    # Recurring payment scopes
    RECURRING_READ = "recurring:read"
    RECURRING_WRITE = "recurring:write"
    RECURRING_DELETE = "recurring:delete"
    
    # User scopes
    PROFILE_READ = "profile:read"
    PROFILE_WRITE = "profile:write"
    
    # Admin scopes
    ADMIN_READ = "admin:read"
    ADMIN_WRITE = "admin:write"
    
    @classmethod
    def get_all_scopes(cls) -> List[str]:
        """Get list of all available scopes."""
        return [
            cls.ACCOUNTS_READ, cls.ACCOUNTS_WRITE, cls.ACCOUNTS_DELETE,
            cls.TRANSACTIONS_READ, cls.TRANSACTIONS_WRITE,
            cls.RECURRING_READ, cls.RECURRING_WRITE, cls.RECURRING_DELETE,
            cls.PROFILE_READ, cls.PROFILE_WRITE,
            cls.ADMIN_READ, cls.ADMIN_WRITE
        ]
    
    @classmethod
    def get_read_scopes(cls) -> List[str]:
        """Get list of read-only scopes."""
        return [
            cls.ACCOUNTS_READ, cls.TRANSACTIONS_READ, cls.RECURRING_READ,
            cls.PROFILE_READ, cls.ADMIN_READ
        ]
    
    @classmethod
    def get_write_scopes(cls) -> List[str]:
        """Get list of write scopes."""
        return [
            cls.ACCOUNTS_WRITE, cls.ACCOUNTS_DELETE,
            cls.TRANSACTIONS_WRITE,
            cls.RECURRING_WRITE, cls.RECURRING_DELETE,
            cls.PROFILE_WRITE, cls.ADMIN_WRITE
        ]
