"""
API Key authentication middleware for PersifonPay.
Handles API key authentication for external integrations.
"""

import time
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.models import AnonymousUser
from .api_key_manager import APIKeyManager
from .utils import get_client_ip


class APIKeyUser:
    """
    Represents an authenticated API key user.
    This is used instead of a regular User object for API key authentication.
    """
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.id = api_key.created_by.id
        self.username = f"api_key_{api_key.prefix}"
        self.is_authenticated = True
        self.is_active = True
        self.is_staff = False
        self.is_superuser = False
        
    @property
    def pk(self):
        return self.id
    
    def __str__(self):
        return self.username
    
    def has_perm(self, perm, obj=None):
        """Check if API key has permission."""
        return self.api_key.has_permission(perm)
    
    def has_perms(self, perm_list, obj=None):
        """Check if API key has all permissions."""
        return all(self.has_perm(perm, obj) for perm in perm_list)
    
    def has_module_perms(self, module):
        """Check if API key has module permissions."""
        return True  # API keys can access modules they have scope for


class APIKeyAuthenticationMiddleware(MiddlewareMixin):
    """
    Middleware to handle API key authentication.
    
    This middleware checks for API keys in the Authorization header
    and authenticates users accordingly.
    """
    
    async_mode = False  # This middleware doesn't support async
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.api_key_manager = APIKeyManager()
    
    def process_request(self, request):
        """Process incoming requests for API key authentication."""
        # Skip if already authenticated via session/JWT
        if hasattr(request, 'user') and request.user.is_authenticated:
            return None
        
        # Check for API key in Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header:
            return None
        
        # Extract API key from header
        if not auth_header.startswith('Bearer '):
            return None
        
        api_key = auth_header[7:]  # Remove 'Bearer ' prefix
        
        # Get client IP for validation
        client_ip = get_client_ip(request)
        
        # Get required scope from request path/method
        required_scope = self._get_required_scope(request)
        
        # Validate API key
        is_valid, api_key_obj, error_message = self.api_key_manager.validate_api_key(
            api_key, client_ip, required_scope
        )
        
        if not is_valid:
            return JsonResponse({
                'error': 'Authentication failed',
                'message': error_message,
                'code': 'INVALID_API_KEY'
            }, status=401)
        
        # Check rate limits
        within_limit, current_usage, rate_limit = self.api_key_manager.check_rate_limit(api_key_obj)
        if not within_limit:
            return JsonResponse({
                'error': 'Rate limit exceeded',
                'message': f'Rate limit of {rate_limit} requests per hour exceeded',
                'code': 'RATE_LIMIT_EXCEEDED',
                'current_usage': current_usage,
                'rate_limit': rate_limit
            }, status=429)
        
        # Set authenticated user
        request.user = APIKeyUser(api_key_obj)
        request.api_key = api_key_obj
        
        # Store start time for response time calculation
        request._api_key_start_time = time.time()
        
        return None
    
    def process_response(self, request, response):
        """Process responses to log API usage."""
        # Only log if this was an API key authenticated request
        if hasattr(request, 'api_key') and hasattr(request, '_api_key_start_time'):
            # Calculate response time
            response_time_ms = int((time.time() - request._api_key_start_time) * 1000)
            
            # Log API usage
            self.api_key_manager.log_api_usage(
                request.api_key,
                request,
                response,
                response_time_ms
            )
        
        return response
    
    def _get_required_scope(self, request):
        """
        Determine the required scope based on request path and method.
        
        Args:
            request: Django request object
            
        Returns:
            str: Required scope or None if no specific scope required
        """
        from .api_key_manager import APIKeyScopes
        
        path = request.path.lower()
        method = request.method.upper()
        
        # Account endpoints
        if '/api/account' in path:
            if method in ['GET']:
                return APIKeyScopes.ACCOUNTS_READ
            elif method in ['POST', 'PUT', 'PATCH']:
                return APIKeyScopes.ACCOUNTS_WRITE
            elif method in ['DELETE']:
                return APIKeyScopes.ACCOUNTS_DELETE
        
        # Transaction endpoints
        elif '/api/transaction' in path:
            if method in ['GET']:
                return APIKeyScopes.TRANSACTIONS_READ
            elif method in ['POST', 'PUT', 'PATCH']:
                return APIKeyScopes.TRANSACTIONS_WRITE
        
        # Recurring payment endpoints
        elif '/api/recurring-payment' in path:
            if method in ['GET']:
                return APIKeyScopes.RECURRING_READ
            elif method in ['POST', 'PUT', 'PATCH']:
                return APIKeyScopes.RECURRING_WRITE
            elif method in ['DELETE']:
                return APIKeyScopes.RECURRING_DELETE
        
        # Profile endpoints
        elif '/api/profile' in path:
            if method in ['GET']:
                return APIKeyScopes.PROFILE_READ
            elif method in ['POST', 'PUT', 'PATCH']:
                return APIKeyScopes.PROFILE_WRITE
        
        # Admin endpoints
        elif '/admin' in path or '/api/admin' in path:
            if method in ['GET']:
                return APIKeyScopes.ADMIN_READ
            else:
                return APIKeyScopes.ADMIN_WRITE
        
        return None


class APIKeyRateLimitMiddleware(MiddlewareMixin):
    """
    Additional middleware for API key rate limiting.
    Can be used independently or with APIKeyAuthenticationMiddleware.
    """
    
    async_mode = False  # This middleware doesn't support async
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.api_key_manager = APIKeyManager()
    
    def process_request(self, request):
        """Check rate limits for API key requests."""
        # Only apply to API key authenticated requests
        if not hasattr(request, 'api_key'):
            return None
        
        api_key = request.api_key
        
        # Check rate limits
        within_limit, current_usage, rate_limit = self.api_key_manager.check_rate_limit(api_key)
        
        if not within_limit:
            return JsonResponse({
                'error': 'Rate limit exceeded',
                'message': f'Rate limit of {rate_limit} requests per hour exceeded',
                'code': 'RATE_LIMIT_EXCEEDED',
                'current_usage': current_usage,
                'rate_limit': rate_limit,
                'retry_after': 3600  # 1 hour in seconds
            }, status=429)
        
        # Add rate limit headers to response
        request._rate_limit_info = {
            'limit': rate_limit,
            'remaining': rate_limit - current_usage,
            'reset': int(time.time()) + 3600  # 1 hour from now
        }
        
        return None
    
    def process_response(self, request, response):
        """Add rate limit headers to response."""
        if hasattr(request, '_rate_limit_info'):
            rate_info = request._rate_limit_info
            response['X-RateLimit-Limit'] = str(rate_info['limit'])
            response['X-RateLimit-Remaining'] = str(rate_info['remaining'])
            response['X-RateLimit-Reset'] = str(rate_info['reset'])
        
        return response
