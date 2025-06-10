"""
Comprehensive tests for API key management system in PersifonPay.
"""

import json
import uuid
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from .models import APIKey, APIKeyUsage
from .api_key_manager import APIKeyManager, APIKeyScopes

User = get_user_model()


class APIKeyManagerTests(TestCase):
    """Test the APIKeyManager utility class."""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.api_key_manager = APIKeyManager()
    
    def test_generate_api_key(self):
        """Test API key generation."""
        raw_key, api_key = self.api_key_manager.generate_api_key(
            user=self.user,
            name='Test API Key',
            description='Test description',
            permissions='READ',
            scopes=[APIKeyScopes.ACCOUNTS_READ],
            rate_limit=500
        )
        
        # Check raw key format
        self.assertIsInstance(raw_key, str)
        self.assertGreater(len(raw_key), 20)
        
        # Check API key object
        self.assertEqual(api_key.name, 'Test API Key')
        self.assertEqual(api_key.description, 'Test description')
        self.assertEqual(api_key.permissions, 'READ')
        self.assertEqual(api_key.scopes, [APIKeyScopes.ACCOUNTS_READ])
        self.assertEqual(api_key.rate_limit, 500)
        self.assertEqual(api_key.status, 'ACTIVE')
        self.assertEqual(api_key.created_by, self.user)
        
        # Check prefix extraction
        self.assertEqual(api_key.prefix, raw_key[:8])
        
        # Verify key is saved to database
        self.assertTrue(APIKey.objects.filter(id=api_key.id).exists())
    
    def test_validate_api_key_success(self):
        """Test successful API key validation."""
        raw_key, api_key = self.api_key_manager.generate_api_key(
            user=self.user,
            name='Valid Key',
            permissions='READ_WRITE',
            scopes=[APIKeyScopes.ACCOUNTS_READ, APIKeyScopes.TRANSACTIONS_READ]
        )
        
        # Test validation
        is_valid, validated_key, error = self.api_key_manager.validate_api_key(
            raw_key,
            ip_address='192.168.1.1',
            scope=APIKeyScopes.ACCOUNTS_READ
        )
        
        self.assertTrue(is_valid)
        self.assertEqual(validated_key.id, api_key.id)
        self.assertEqual(error, '')
    
    def test_validate_api_key_invalid_key(self):
        """Test validation with invalid API key."""
        is_valid, api_key, error = self.api_key_manager.validate_api_key(
            'invalid_key_12345',
            ip_address='192.168.1.1'
        )
        
        self.assertFalse(is_valid)
        self.assertIsNone(api_key)
        self.assertEqual(error, 'Invalid API key')
    
    def test_validate_api_key_revoked(self):
        """Test validation with revoked API key."""
        raw_key, api_key = self.api_key_manager.generate_api_key(
            user=self.user,
            name='Revoked Key'
        )
        
        # Revoke the key
        api_key.status = 'REVOKED'
        api_key.save()
        
        # Test validation
        is_valid, validated_key, error = self.api_key_manager.validate_api_key(raw_key)
        
        self.assertFalse(is_valid)
        self.assertIsNone(validated_key)
        self.assertEqual(error, 'API key is revoked')
    
    def test_validate_api_key_ip_restriction(self):
        """Test IP address restrictions."""
        raw_key, api_key = self.api_key_manager.generate_api_key(
            user=self.user,
            name='IP Restricted Key',
            allowed_ips=['192.168.1.1', '10.0.0.1']
        )
        
        # Test allowed IP
        is_valid, _, error = self.api_key_manager.validate_api_key(
            raw_key, ip_address='192.168.1.1'
        )
        self.assertTrue(is_valid)
        
        # Test forbidden IP
        is_valid, _, error = self.api_key_manager.validate_api_key(
            raw_key, ip_address='203.0.113.1'
        )
        self.assertFalse(is_valid)
        self.assertEqual(error, 'IP address not allowed')
    
    def test_validate_api_key_scope_permission(self):
        """Test scope-based permissions."""
        raw_key, api_key = self.api_key_manager.generate_api_key(
            user=self.user,
            name='Scoped Key',
            scopes=[APIKeyScopes.ACCOUNTS_READ]
        )
        
        # Test allowed scope
        is_valid, _, error = self.api_key_manager.validate_api_key(
            raw_key, scope=APIKeyScopes.ACCOUNTS_READ
        )
        self.assertTrue(is_valid)
        
        # Test forbidden scope
        is_valid, _, error = self.api_key_manager.validate_api_key(
            raw_key, scope=APIKeyScopes.TRANSACTIONS_WRITE
        )
        self.assertFalse(is_valid)
        self.assertIn('Insufficient permissions', error)
    
    def test_revoke_api_key(self):
        """Test API key revocation."""
        raw_key, api_key = self.api_key_manager.generate_api_key(
            user=self.user,
            name='Key to Revoke'
        )
        
        # Revoke the key
        success = self.api_key_manager.revoke_api_key(
            str(api_key.id),
            self.user,
            reason='Test revocation'
        )
        
        self.assertTrue(success)
        
        # Verify key is revoked
        api_key.refresh_from_db()
        self.assertEqual(api_key.status, 'REVOKED')
    
    def test_check_rate_limit(self):
        """Test rate limiting functionality."""
        raw_key, api_key = self.api_key_manager.generate_api_key(
            user=self.user,
            name='Rate Limited Key',
            rate_limit=5
        )
        
        # Create usage records
        for i in range(3):
            APIKeyUsage.objects.create(
                api_key=api_key,
                ip_address='192.168.1.1',
                method='GET',
                path='/api/test/',
                status_code=200
            )
        
        # Check rate limit (should be within limit)
        within_limit, current_usage, rate_limit = self.api_key_manager.check_rate_limit(api_key)
        
        self.assertTrue(within_limit)
        self.assertEqual(current_usage, 3)
        self.assertEqual(rate_limit, 5)
        
        # Add more usage to exceed limit
        for i in range(3):
            APIKeyUsage.objects.create(
                api_key=api_key,
                ip_address='192.168.1.1',
                method='GET',
                path='/api/test/',
                status_code=200
            )
        
        # Check rate limit (should be exceeded)
        within_limit, current_usage, rate_limit = self.api_key_manager.check_rate_limit(api_key)
        
        self.assertFalse(within_limit)
        self.assertEqual(current_usage, 6)
        self.assertEqual(rate_limit, 5)
    
    def test_get_usage_stats(self):
        """Test usage statistics generation."""
        raw_key, api_key = self.api_key_manager.generate_api_key(
            user=self.user,
            name='Stats Key'
        )
        
        # Create various usage records
        APIKeyUsage.objects.create(
            api_key=api_key,
            ip_address='192.168.1.1',
            method='GET',
            path='/api/accounts/',
            status_code=200,
            response_time_ms=150
        )
        APIKeyUsage.objects.create(
            api_key=api_key,
            ip_address='192.168.1.1',
            method='POST',
            path='/api/transactions/',
            status_code=201,
            response_time_ms=250
        )
        APIKeyUsage.objects.create(
            api_key=api_key,
            ip_address='192.168.1.1',
            method='GET',
            path='/api/accounts/',
            status_code=404,
            response_time_ms=100
        )
        
        stats = self.api_key_manager.get_usage_stats(api_key)
        
        self.assertEqual(stats['total_requests'], 3)
        self.assertEqual(stats['successful_requests'], 2)
        self.assertEqual(stats['error_requests'], 1)
        self.assertAlmostEqual(stats['success_rate'], 66.67, places=1)
        self.assertEqual(stats['avg_response_time_ms'], 166.67)
        self.assertEqual(len(stats['popular_endpoints']), 2)


class APIKeyAPITests(APITestCase):
    """Test the API key management API endpoints."""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.client.force_authenticate(user=self.user)
    
    def test_create_api_key(self):
        """Test API key creation via API."""
        url = '/api/api-keys/'
        data = {
            'name': 'Test API Key',
            'description': 'API key for testing',
            'permissions': 'READ',
            'scopes': [APIKeyScopes.ACCOUNTS_READ],
            'rate_limit': 1000
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('api_key', response.data)
        self.assertIn('key', response.data['api_key'])
        self.assertEqual(response.data['api_key']['name'], 'Test API Key')
        
        # Verify API key was created in database
        api_key = APIKey.objects.get(name='Test API Key')
        self.assertEqual(api_key.created_by, self.user)
        self.assertEqual(api_key.permissions, 'READ')
    
    def test_create_api_key_validation_errors(self):
        """Test API key creation with validation errors."""
        url = '/api/api-keys/'
        
        # Test missing name
        response = self.client.post(url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Name is required', response.data['error'])
        
        # Test invalid permissions
        data = {
            'name': 'Test Key',
            'permissions': 'INVALID'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Invalid permissions', response.data['error'])
        
        # Test invalid IP address
        data = {
            'name': 'Test Key',
            'allowed_ips': ['invalid_ip']
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Invalid IP address', response.data['error'])
    
    def test_list_api_keys(self):
        """Test listing user's API keys."""
        # Create some API keys
        api_key_manager = APIKeyManager()
        api_key_manager.generate_api_key(self.user, 'Key 1')
        api_key_manager.generate_api_key(self.user, 'Key 2')
        
        url = '/api/api-keys/'
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['total_count'], 2)
        self.assertEqual(len(response.data['api_keys']), 2)
    
    def test_get_api_key_detail(self):
        """Test getting API key details."""
        api_key_manager = APIKeyManager()
        raw_key, api_key = api_key_manager.generate_api_key(self.user, 'Detail Key')
        
        url = f'/api/api-keys/{api_key.id}/'
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'Detail Key')
        self.assertEqual(response.data['id'], str(api_key.id))
    
    def test_update_api_key(self):
        """Test updating API key settings."""
        api_key_manager = APIKeyManager()
        raw_key, api_key = api_key_manager.generate_api_key(self.user, 'Update Key')
        
        url = f'/api/api-keys/{api_key.id}/'
        data = {
            'name': 'Updated Key Name',
            'description': 'Updated description',
            'rate_limit': 2000
        }
        
        response = self.client.patch(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('updated_fields', response.data)
        
        # Verify updates
        api_key.refresh_from_db()
        self.assertEqual(api_key.name, 'Updated Key Name')
        self.assertEqual(api_key.description, 'Updated description')
        self.assertEqual(api_key.rate_limit, 2000)
    
    def test_revoke_api_key(self):
        """Test revoking an API key."""
        api_key_manager = APIKeyManager()
        raw_key, api_key = api_key_manager.generate_api_key(self.user, 'Revoke Key')
        
        url = f'/api/api-keys/{api_key.id}/'
        data = {'reason': 'Test revocation'}
        
        response = self.client.delete(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify key is revoked
        api_key.refresh_from_db()
        self.assertEqual(api_key.status, 'REVOKED')
    
    def test_get_api_key_scopes(self):
        """Test getting available API key scopes."""
        url = '/api/api-keys/scopes/'
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('all_scopes', response.data)
        self.assertIn('read_scopes', response.data)
        self.assertIn('write_scopes', response.data)
        self.assertIn('scope_descriptions', response.data)
    
    def test_get_usage_stats(self):
        """Test getting API key usage statistics."""
        api_key_manager = APIKeyManager()
        raw_key, api_key = api_key_manager.generate_api_key(self.user, 'Stats Key')
        
        # Create some usage
        APIKeyUsage.objects.create(
            api_key=api_key,
            ip_address='192.168.1.1',
            method='GET',
            path='/api/test/',
            status_code=200
        )
        
        url = f'/api/api-keys/{api_key.id}/usage/'
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('total_requests', response.data)
        self.assertIn('successful_requests', response.data)
        self.assertEqual(response.data['total_requests'], 1)
    
    def test_unauthorized_access(self):
        """Test that unauthenticated users cannot access API key endpoints."""
        self.client.force_authenticate(user=None)
        
        url = '/api/api-keys/'
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_cross_user_api_key_access(self):
        """Test that users cannot access other users' API keys."""
        # Create another user and their API key
        other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            password='otherpass123'
        )
        
        api_key_manager = APIKeyManager()
        raw_key, other_api_key = api_key_manager.generate_api_key(other_user, 'Other Key')
        
        # Try to access other user's API key
        url = f'/api/api-keys/{other_api_key.id}/'
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class APIKeyMiddlewareTests(TestCase):
    """Test the API key authentication middleware."""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        # Create API key
        api_key_manager = APIKeyManager()
        self.raw_key, self.api_key = api_key_manager.generate_api_key(
            user=self.user,
            name='Middleware Test Key',
            scopes=[APIKeyScopes.ACCOUNTS_READ, APIKeyScopes.TRANSACTIONS_READ]
        )
    
    def test_api_key_authentication_success(self):
        """Test successful API key authentication via middleware."""
        from django.test import RequestFactory
        from main.api_key_middleware import APIKeyAuthenticationMiddleware
        
        factory = RequestFactory()
        request = factory.get('/api/accounts/', HTTP_AUTHORIZATION=f'Bearer {self.raw_key}')
        
        middleware = APIKeyAuthenticationMiddleware(lambda req: None)
        response = middleware.process_request(request)
        
        # Should not return an error response
        self.assertIsNone(response)
        
        # Should set the authenticated user
        self.assertTrue(hasattr(request, 'user'))
        self.assertTrue(hasattr(request, 'api_key'))
        self.assertEqual(request.api_key.id, self.api_key.id)
    
    def test_api_key_authentication_invalid_key(self):
        """Test authentication with invalid API key."""
        from django.test import RequestFactory
        from main.api_key_middleware import APIKeyAuthenticationMiddleware
        
        factory = RequestFactory()
        request = factory.get('/api/accounts/', HTTP_AUTHORIZATION='Bearer invalid_key')
        
        middleware = APIKeyAuthenticationMiddleware(lambda req: None)
        response = middleware.process_request(request)
        
        # Should return an error response
        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 401)
    
    def test_api_key_rate_limiting(self):
        """Test rate limiting via middleware."""
        from django.test import RequestFactory
        from main.api_key_middleware import APIKeyAuthenticationMiddleware
        
        # Set low rate limit
        self.api_key.rate_limit = 1
        self.api_key.save()
        
        # Create usage record to exceed limit
        APIKeyUsage.objects.create(
            api_key=self.api_key,
            ip_address='192.168.1.1',
            method='GET',
            path='/api/test/',
            status_code=200
        )
        
        factory = RequestFactory()
        request = factory.get('/api/accounts/', HTTP_AUTHORIZATION=f'Bearer {self.raw_key}')
        
        middleware = APIKeyAuthenticationMiddleware(lambda req: None)
        response = middleware.process_request(request)
        
        # Should return rate limit error
        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 429)


class APIKeyScopeTests(TestCase):
    """Test API key scope functionality."""
    
    def test_scope_constants(self):
        """Test that all scope constants are properly defined."""
        scopes = APIKeyScopes.get_all_scopes()
        
        self.assertIn(APIKeyScopes.ACCOUNTS_READ, scopes)
        self.assertIn(APIKeyScopes.ACCOUNTS_WRITE, scopes)
        self.assertIn(APIKeyScopes.TRANSACTIONS_READ, scopes)
        self.assertIn(APIKeyScopes.TRANSACTIONS_WRITE, scopes)
        self.assertIn(APIKeyScopes.RECURRING_READ, scopes)
        self.assertIn(APIKeyScopes.RECURRING_WRITE, scopes)
        
        # Test read/write scope separation
        read_scopes = APIKeyScopes.get_read_scopes()
        write_scopes = APIKeyScopes.get_write_scopes()
        
        self.assertIn(APIKeyScopes.ACCOUNTS_READ, read_scopes)
        self.assertNotIn(APIKeyScopes.ACCOUNTS_WRITE, read_scopes)
        self.assertIn(APIKeyScopes.ACCOUNTS_WRITE, write_scopes)
        self.assertNotIn(APIKeyScopes.ACCOUNTS_READ, write_scopes)


class APIKeyModelTests(TestCase):
    """Test API key model functionality."""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_api_key_model_creation(self):
        """Test API key model creation and methods."""
        api_key = APIKey.objects.create(
            name='Test Key',
            key_hash='test_hash',
            prefix='testpref',
            created_by=self.user,
            permissions='READ',
            scopes=[APIKeyScopes.ACCOUNTS_READ],
            allowed_ips=['192.168.1.1'],
            rate_limit=1000
        )
        
        self.assertEqual(str(api_key), 'Test Key')
        self.assertTrue(api_key.is_valid())
        self.assertTrue(api_key.is_ip_allowed('192.168.1.1'))
        self.assertFalse(api_key.is_ip_allowed('10.0.0.1'))
        self.assertTrue(api_key.has_scope(APIKeyScopes.ACCOUNTS_READ))
        self.assertFalse(api_key.has_scope(APIKeyScopes.TRANSACTIONS_WRITE))
    
    def test_api_key_expiration(self):
        """Test API key expiration functionality."""
        # Create expired key
        expired_key = APIKey.objects.create(
            name='Expired Key',
            key_hash='expired_hash',
            prefix='expired_',
            created_by=self.user,
            expires_at=timezone.now() - timezone.timedelta(hours=1)
        )
        
        self.assertFalse(expired_key.is_valid())
        self.assertEqual(expired_key.status, 'EXPIRED')
    
    def test_api_key_usage_increment(self):
        """Test usage count increment."""
        api_key = APIKey.objects.create(
            name='Usage Key',
            key_hash='usage_hash',
            prefix='usage___',
            created_by=self.user
        )
        
        initial_count = api_key.usage_count
        api_key.increment_usage()
        
        self.assertEqual(api_key.usage_count, initial_count + 1)
        self.assertIsNotNone(api_key.last_used)
