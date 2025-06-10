"""
API views for managing API keys in PersifonPay.
Provides CRUD operations for API key management.
"""

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils.dateparse import parse_datetime
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.http import Http404

from .api_key_manager import APIKeyManager, APIKeyScopes
from .models import APIKey
from .throttling import APIKeyManagementThrottle
from .audit import AuditLogger
from .validators import InputValidator


class APIKeyManagementView(APIView):
    """
    Manage API keys for the authenticated user.
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [APIKeyManagementThrottle]
    
    def __init__(self):
        super().__init__()
        self.api_key_manager = APIKeyManager()
        self.audit_logger = AuditLogger()
    
    def get(self, request):
        """
        List all API keys for the authenticated user.
        
        Query parameters:
        - include_revoked: Include revoked keys (default: false)
        - include_usage: Include usage statistics (default: false)
        """
        try:
            include_revoked = request.GET.get('include_revoked', 'false').lower() == 'true'
            include_usage = request.GET.get('include_usage', 'false').lower() == 'true'
            
            # Get user's API keys
            api_keys = self.api_key_manager.list_user_keys(
                request.user, 
                include_revoked=include_revoked
            )
            
            # Serialize API keys
            keys_data = []
            for api_key in api_keys:
                key_data = {
                    'id': str(api_key.id),
                    'name': api_key.name,
                    'description': api_key.description,
                    'prefix': api_key.prefix,
                    'permissions': api_key.permissions,
                    'scopes': api_key.scopes,
                    'allowed_ips': api_key.allowed_ips,
                    'status': api_key.status,
                    'created_at': api_key.created_at.isoformat(),
                    'expires_at': api_key.expires_at.isoformat() if api_key.expires_at else None,
                    'last_used': api_key.last_used.isoformat() if api_key.last_used else None,
                    'usage_count': api_key.usage_count,
                    'rate_limit': api_key.rate_limit,
                    'is_valid': api_key.is_valid()
                }
                
                # Add usage statistics if requested
                if include_usage:
                    usage_stats = self.api_key_manager.get_usage_stats(api_key)
                    key_data['usage_stats'] = usage_stats
                
                keys_data.append(key_data)
            
            return Response({
                'api_keys': keys_data,
                'total_count': len(keys_data)
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            self.audit_logger.log_security_event(
                user=request.user,
                action='VIEW',
                description=f'Failed to retrieve API keys: {str(e)}',
                severity='ERROR',
                metadata={'error': str(e)}
            )
            return Response({
                'error': 'Failed to retrieve API keys',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request):
        """
        Create a new API key.
        
        Request body:
        {
            "name": "string (required)",
            "description": "string (optional)",
            "permissions": "READ|READ_WRITE|ADMIN (optional, default: READ)",
            "scopes": ["scope1", "scope2"] (optional),
            "allowed_ips": ["ip1", "ip2"] (optional),
            "expires_at": "ISO datetime string (optional)",
            "rate_limit": integer (optional, default: 1000)
        }
        """
        try:
            # Validate required fields
            if 'name' not in request.data:
                return Response({
                    'error': 'Name is required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            name = request.data['name'].strip()
            if not name:
                return Response({
                    'error': 'Name cannot be empty'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if user already has an API key with this name
            existing_key = APIKey.objects.filter(
                created_by=request.user,
                name=name,
                status__in=['ACTIVE', 'EXPIRED']
            ).first()
            
            if existing_key:
                return Response({
                    'error': f'API key with name "{name}" already exists'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Extract and validate parameters
            description = request.data.get('description', '')
            permissions = request.data.get('permissions', 'READ')
            scopes = request.data.get('scopes', [])
            allowed_ips = request.data.get('allowed_ips', [])
            rate_limit = request.data.get('rate_limit', 1000)
            
            # Validate permissions
            if permissions not in ['READ', 'READ_WRITE', 'ADMIN']:
                return Response({
                    'error': 'Invalid permissions. Must be READ, READ_WRITE, or ADMIN'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate scopes
            if scopes:
                valid_scopes = APIKeyScopes.get_all_scopes()
                invalid_scopes = [scope for scope in scopes if scope not in valid_scopes]
                if invalid_scopes:
                    return Response({
                        'error': f'Invalid scopes: {invalid_scopes}',
                        'valid_scopes': valid_scopes
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate IP addresses
            if allowed_ips:
                for ip in allowed_ips:
                    try:
                        InputValidator.validate_ip_address(ip)
                    except ValidationError:
                        return Response({
                            'error': f'Invalid IP address: {ip}'
                        }, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate rate limit
            if not isinstance(rate_limit, int) or rate_limit <= 0:
                return Response({
                    'error': 'Rate limit must be a positive integer'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Parse expiration date
            expires_at = None
            if 'expires_at' in request.data:
                expires_at = parse_datetime(request.data['expires_at'])
                if not expires_at:
                    return Response({
                        'error': 'Invalid expires_at format. Use ISO datetime format'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                if expires_at <= timezone.now():
                    return Response({
                        'error': 'Expiration date must be in the future'
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            # Generate API key
            raw_key, api_key = self.api_key_manager.generate_api_key(
                user=request.user,
                name=name,
                description=description,
                permissions=permissions,
                scopes=scopes,
                allowed_ips=allowed_ips,
                expires_at=expires_at,
                rate_limit=rate_limit
            )
            
            return Response({
                'message': 'API key created successfully',
                'api_key': {
                    'id': str(api_key.id),
                    'name': api_key.name,
                    'key': raw_key,  # Only returned once!
                    'prefix': api_key.prefix,
                    'permissions': api_key.permissions,
                    'scopes': api_key.scopes,
                    'allowed_ips': api_key.allowed_ips,
                    'created_at': api_key.created_at.isoformat(),
                    'expires_at': api_key.expires_at.isoformat() if api_key.expires_at else None,
                    'rate_limit': api_key.rate_limit
                },
                'warning': 'Save this API key securely. It will not be shown again.'
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            self.audit_logger.log_security_event(
                user=request.user,
                action='CREATE',
                description=f'Failed to create API key: {str(e)}',
                severity='ERROR',
                metadata={'error': str(e)}
            )
            return Response({
                'error': 'Failed to create API key',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class APIKeyDetailView(APIView):
    """
    Manage individual API keys.
    """
    permission_classes = [IsAuthenticated]
    throttle_classes = [APIKeyManagementThrottle]
    
    def __init__(self):
        super().__init__()
        self.api_key_manager = APIKeyManager()
        self.audit_logger = AuditLogger()
    
    def get_api_key(self, request, api_key_id):
        """Get API key instance if user has access."""
        try:
            return APIKey.objects.get(id=api_key_id, created_by=request.user)
        except APIKey.DoesNotExist:
            raise Http404("API key not found")
    
    def get(self, request, api_key_id):
        """
        Get details of a specific API key.
        
        Query parameters:
        - include_usage: Include usage statistics (default: false)
        """
        try:
            api_key = self.get_api_key(request, api_key_id)
            include_usage = request.GET.get('include_usage', 'false').lower() == 'true'
            
            key_data = {
                'id': str(api_key.id),
                'name': api_key.name,
                'description': api_key.description,
                'prefix': api_key.prefix,
                'permissions': api_key.permissions,
                'scopes': api_key.scopes,
                'allowed_ips': api_key.allowed_ips,
                'status': api_key.status,
                'created_at': api_key.created_at.isoformat(),
                'expires_at': api_key.expires_at.isoformat() if api_key.expires_at else None,
                'last_used': api_key.last_used.isoformat() if api_key.last_used else None,
                'usage_count': api_key.usage_count,
                'rate_limit': api_key.rate_limit,
                'is_valid': api_key.is_valid()
            }
            
            # Add usage statistics if requested
            if include_usage:
                usage_stats = self.api_key_manager.get_usage_stats(api_key)
                key_data['usage_stats'] = usage_stats
            
            return Response(key_data, status=status.HTTP_200_OK)
            
        except Http404:
            return Response({
                'error': 'API key not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': 'Failed to retrieve API key',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def patch(self, request, api_key_id):
        """
        Update API key settings.
        
        Updatable fields:
        - name
        - description
        - allowed_ips
        - rate_limit
        - expires_at
        """
        try:
            api_key = self.get_api_key(request, api_key_id)
            
            # Check if key is revoked
            if api_key.status == 'REVOKED':
                return Response({
                    'error': 'Cannot update revoked API key'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            updated_fields = []
            
            # Update name
            if 'name' in request.data:
                new_name = request.data['name'].strip()
                if not new_name:
                    return Response({
                        'error': 'Name cannot be empty'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Check for duplicate names
                if new_name != api_key.name:
                    existing_key = APIKey.objects.filter(
                        created_by=request.user,
                        name=new_name,
                        status__in=['ACTIVE', 'EXPIRED']
                    ).exclude(id=api_key.id).first()
                    
                    if existing_key:
                        return Response({
                            'error': f'API key with name "{new_name}" already exists'
                        }, status=status.HTTP_400_BAD_REQUEST)
                
                api_key.name = new_name
                updated_fields.append('name')
            
            # Update description
            if 'description' in request.data:
                api_key.description = request.data['description']
                updated_fields.append('description')
            
            # Update allowed IPs
            if 'allowed_ips' in request.data:
                allowed_ips = request.data['allowed_ips']
                if allowed_ips:
                    for ip in allowed_ips:
                        try:
                            InputValidator.validate_ip_address(ip)
                        except ValidationError:
                            return Response({
                                'error': f'Invalid IP address: {ip}'
                            }, status=status.HTTP_400_BAD_REQUEST)
                
                api_key.allowed_ips = allowed_ips
                updated_fields.append('allowed_ips')
            
            # Update rate limit
            if 'rate_limit' in request.data:
                rate_limit = request.data['rate_limit']
                if not isinstance(rate_limit, int) or rate_limit <= 0:
                    return Response({
                        'error': 'Rate limit must be a positive integer'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                api_key.rate_limit = rate_limit
                updated_fields.append('rate_limit')
            
            # Update expiration
            if 'expires_at' in request.data:
                if request.data['expires_at'] is None:
                    api_key.expires_at = None
                    updated_fields.append('expires_at')
                else:
                    expires_at = parse_datetime(request.data['expires_at'])
                    if not expires_at:
                        return Response({
                            'error': 'Invalid expires_at format. Use ISO datetime format'
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
                    if expires_at <= timezone.now():
                        return Response({
                            'error': 'Expiration date must be in the future'
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
                    api_key.expires_at = expires_at
                    updated_fields.append('expires_at')
            
            # Save changes
            if updated_fields:
                api_key.save(update_fields=updated_fields)
                
                # Log update
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='UPDATE',
                    description=f'API key updated: {api_key.name}',
                    severity='INFO',
                    metadata={
                        'api_key_id': str(api_key.id),
                        'updated_fields': updated_fields
                    }
                )
            
            return Response({
                'message': 'API key updated successfully',
                'updated_fields': updated_fields
            }, status=status.HTTP_200_OK)
            
        except Http404:
            return Response({
                'error': 'API key not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': 'Failed to update API key',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def delete(self, request, api_key_id):
        """
        Revoke an API key.
        
        Request body:
        {
            "reason": "string (optional)"
        }
        """
        try:
            api_key = self.get_api_key(request, api_key_id)
            
            if api_key.status == 'REVOKED':
                return Response({
                    'error': 'API key is already revoked'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            reason = request.data.get('reason', 'Revoked by user')
            
            # Revoke the API key
            success = self.api_key_manager.revoke_api_key(
                str(api_key.id),
                request.user,
                reason
            )
            
            if success:
                return Response({
                    'message': 'API key revoked successfully'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'error': 'Failed to revoke API key'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except Http404:
            return Response({
                'error': 'API key not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': 'Failed to revoke API key',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_key_scopes(request):
    """
    Get available API key scopes.
    """
    return Response({
        'all_scopes': APIKeyScopes.get_all_scopes(),
        'read_scopes': APIKeyScopes.get_read_scopes(),
        'write_scopes': APIKeyScopes.get_write_scopes(),
        'scope_descriptions': {
            'accounts:read': 'Read account information',
            'accounts:write': 'Create and update accounts',
            'accounts:delete': 'Delete accounts',
            'transactions:read': 'Read transaction history',
            'transactions:write': 'Create transactions',
            'recurring:read': 'Read recurring payments',
            'recurring:write': 'Create and update recurring payments',
            'recurring:delete': 'Delete recurring payments',
            'profile:read': 'Read user profile',
            'profile:write': 'Update user profile',
            'admin:read': 'Admin read access',
            'admin:write': 'Admin write access'
        }
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_key_usage_stats(request, api_key_id):
    """
    Get detailed usage statistics for an API key.
    
    Query parameters:
    - days: Number of days to analyze (default: 30, max: 365)
    """
    try:
        # Get API key
        try:
            api_key = APIKey.objects.get(id=api_key_id, created_by=request.user)
        except APIKey.DoesNotExist:
            return Response({
                'error': 'API key not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Get number of days
        days = min(int(request.GET.get('days', 30)), 365)
        
        # Get usage statistics
        api_key_manager = APIKeyManager()
        usage_stats = api_key_manager.get_usage_stats(api_key, days)
        
        return Response(usage_stats, status=status.HTTP_200_OK)
        
    except ValueError:
        return Response({
            'error': 'Invalid days parameter'
        }, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({
            'error': 'Failed to retrieve usage statistics',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
