"""
Tests for Two-Factor Authentication functionality.
"""

import json
import pyotp
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from .two_factor import TwoFactorAuth

User = get_user_model()


class TwoFactorAuthTest(TestCase):
    """Test TwoFactorAuth utility class"""
    
    def setUp(self):
        self.two_factor_auth = TwoFactorAuth()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPass123!'
        )
    
    def test_generate_secret(self):
        """Test secret generation"""
        secret = self.two_factor_auth.generate_secret()
        self.assertTrue(secret)
        self.assertEqual(len(secret), 32)  # Base32 encoded secret
    
    def test_totp_verification(self):
        """Test TOTP token verification"""
        secret = self.two_factor_auth.generate_secret()
        
        # Generate current TOTP token
        totp = pyotp.TOTP(secret)
        current_token = totp.now()
        
        # Verify token
        self.assertTrue(self.two_factor_auth.verify_totp(secret, current_token))
        
        # Verify invalid token
        self.assertFalse(self.two_factor_auth.verify_totp(secret, "000000"))
    
    def test_backup_codes_generation(self):
        """Test backup codes generation and verification"""
        # Generate backup codes
        codes = self.two_factor_auth.generate_backup_codes()
        self.assertEqual(len(codes), 10)
        
        # Check format (XXXX-XXXX)
        for code in codes:
            self.assertRegex(code, r'^[A-Z0-9]{4}-[A-Z0-9]{4}$')
        
        # Hash codes
        hashed_codes = self.two_factor_auth.hash_backup_codes(codes)
        self.assertEqual(len(hashed_codes), 10)
        
        # Verify a backup code
        test_code = codes[0]
        is_valid, hash_to_remove = self.two_factor_auth.verify_backup_code(
            hashed_codes, test_code
        )
        self.assertTrue(is_valid)
        self.assertIn(hash_to_remove, hashed_codes)
    
    def test_qr_code_generation(self):
        """Test QR code generation"""
        secret = self.two_factor_auth.generate_secret()
        qr_code = self.two_factor_auth.generate_qr_code(self.user, secret)
        
        # Should return base64 encoded string
        self.assertTrue(qr_code)
        self.assertIsInstance(qr_code, str)


class TwoFactorAPITest(APITestCase):
    """Test 2FA API endpoints"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPass123!'
        )
        self.two_factor_auth = TwoFactorAuth()
        
        # Get JWT token for authentication
        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
    
    def test_2fa_setup_initiation(self):
        """Test 2FA setup initiation"""
        url = reverse('api/2fa/setup/')
        response = self.client.post(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        
        self.assertIn('secret', data['data'])
        self.assertIn('qr_code', data['data'])
        self.assertIn('backup_codes', data['data'])
        self.assertEqual(len(data['data']['backup_codes']), 10)
        
        # Check user was updated
        self.user.refresh_from_db()
        self.assertTrue(self.user.two_factor_secret)
        self.assertEqual(len(self.user.backup_codes), 10)
        self.assertFalse(self.user.two_factor_enabled)  # Not enabled yet
    
    def test_2fa_setup_verification(self):
        """Test 2FA setup verification and enablement"""
        # First initiate setup
        setup_url = reverse('api/2fa/setup/')
        setup_response = self.client.post(setup_url)
        secret = setup_response.json()['data']['secret']
        
        # Generate valid TOTP token
        totp = pyotp.TOTP(secret)
        token = totp.now()
        
        # Verify setup
        verify_url = reverse('api/2fa/verify-setup/')
        response = self.client.post(verify_url, {'token': token})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check user was updated
        self.user.refresh_from_db()
        self.assertTrue(self.user.two_factor_enabled)
        self.assertTrue(self.user.two_factor_enabled_date)
    
    def test_2fa_status(self):
        """Test 2FA status endpoint"""
        url = reverse('api/2fa/status/')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        
        self.assertFalse(data['data']['enabled'])
        self.assertTrue(data['data']['requires_setup'])
    
    def test_2fa_disable(self):
        """Test 2FA disabling"""
        # First enable 2FA
        self.user.two_factor_enabled = True
        self.user.two_factor_secret = self.two_factor_auth.generate_secret()
        self.user.save()
        
        # Generate valid TOTP token
        totp = pyotp.TOTP(self.user.two_factor_secret)
        token = totp.now()
        
        # Disable 2FA
        url = reverse('api/2fa/disable/')
        response = self.client.post(url, {
            'password': 'TestPass123!',
            'token': token
        })
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check user was updated
        self.user.refresh_from_db()
        self.assertFalse(self.user.two_factor_enabled)
        self.assertEqual(self.user.two_factor_secret, '')
        self.assertEqual(self.user.backup_codes, [])
    
    def test_unauthorized_access(self):
        """Test that 2FA endpoints require authentication"""
        self.client.credentials()  # Remove authentication
        
        endpoints = [
            'api/2fa/setup/',
            'api/2fa/verify-setup/',
            'api/2fa/disable/',
            'api/2fa/status/',
            'api/2fa/backup-codes/',
            'api/2fa/verify/',
        ]
        
        for endpoint in endpoints:
            url = reverse(endpoint)
            response = self.client.post(url)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TwoFactorIntegrationTest(APITestCase):
    """Integration tests for 2FA with other system components"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPass123!'
        )
        self.two_factor_auth = TwoFactorAuth()
        
        # Enable 2FA for user
        self.user.two_factor_enabled = True
        self.user.two_factor_secret = self.two_factor_auth.generate_secret()
        backup_codes = self.two_factor_auth.generate_backup_codes()
        self.user.backup_codes = self.two_factor_auth.hash_backup_codes(backup_codes)
        self.user.save()
        
        # Get JWT token
        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
    
    def test_backup_code_usage(self):
        """Test using backup codes for verification"""
        # Get backup codes
        backup_codes = self.two_factor_auth.generate_backup_codes()
        hashed_codes = self.two_factor_auth.hash_backup_codes(backup_codes)
        self.user.backup_codes = hashed_codes
        self.user.save()
        
        # Use backup code for verification
        url = reverse('api/2fa/verify/')
        response = self.client.post(url, {
            'token': backup_codes[0],
            'operation': 'test_operation'
        })
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check backup code was removed
        self.user.refresh_from_db()
        self.assertEqual(len(self.user.backup_codes), 9)  # One code used
    
    def test_replay_attack_prevention(self):
        """Test TOTP replay attack prevention"""
        # Generate valid TOTP token
        totp = pyotp.TOTP(self.user.two_factor_secret)
        token = totp.now()
        
        # First verification should succeed
        url = reverse('api/2fa/verify/')
        response1 = self.client.post(url, {'token': token})
        self.assertEqual(response1.status_code, status.HTTP_200_OK)
        
        # Second verification with same token should fail
        response2 = self.client.post(url, {'token': token})
        self.assertEqual(response2.status_code, status.HTTP_401_UNAUTHORIZED)
