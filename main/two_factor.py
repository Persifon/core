"""
Two-Factor Authentication (2FA) utilities for PersifonPay.
Provides TOTP-based 2FA functionality with backup codes.
"""

import pyotp
import qrcode
import base64
import secrets
import hashlib
from io import BytesIO
from django.conf import settings
from django.utils import timezone
from typing import List, Tuple, Optional


class TwoFactorAuth:
    """
    Handles TOTP-based two-factor authentication operations.
    """
    
    def __init__(self):
        self.issuer_name = getattr(settings, 'TWO_FACTOR_ISSUER', 'PersifonPay')
        self.backup_codes_count = 10
    
    def generate_secret(self) -> str:
        """Generate a new TOTP secret for a user."""
        return pyotp.random_base32()
    
    def get_totp_uri(self, user, secret: str) -> str:
        """
        Generate TOTP URI for QR code generation.
        
        Args:
            user: User instance
            secret: TOTP secret
            
        Returns:
            TOTP URI string
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=user.email or user.username,
            issuer_name=self.issuer_name
        )
    
    def generate_qr_code(self, user, secret: str) -> str:
        """
        Generate QR code for 2FA setup.
        
        Args:
            user: User instance
            secret: TOTP secret
            
        Returns:
            Base64 encoded QR code image
        """
        uri = self.get_totp_uri(user, secret)
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    def verify_totp(self, secret: str, token: str, window: int = 1) -> bool:
        """
        Verify TOTP token.
        
        Args:
            secret: TOTP secret
            token: 6-digit TOTP token
            window: Time window for verification (default: 1 = 30 seconds before/after)
            
        Returns:
            True if token is valid, False otherwise
        """
        if not secret or not token:
            return False
            
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=window)
        except Exception:
            return False
    
    def generate_backup_codes(self) -> List[str]:
        """
        Generate backup codes for 2FA recovery.
        
        Returns:
            List of 10 backup codes
        """
        codes = []
        for _ in range(self.backup_codes_count):
            # Generate 8-character backup code
            code = secrets.token_hex(4).upper()
            # Format as XXXX-XXXX
            formatted_code = f"{code[:4]}-{code[4:]}"
            codes.append(formatted_code)
        
        return codes
    
    def hash_backup_codes(self, codes: List[str]) -> List[str]:
        """
        Hash backup codes for secure storage.
        
        Args:
            codes: List of backup codes
            
        Returns:
            List of hashed backup codes
        """
        hashed_codes = []
        for code in codes:
            # Remove formatting and hash
            clean_code = code.replace('-', '').upper()
            hashed = hashlib.sha256(clean_code.encode()).hexdigest()
            hashed_codes.append(hashed)
        
        return hashed_codes
    
    def verify_backup_code(self, stored_hashed_codes: List[str], provided_code: str) -> Tuple[bool, Optional[str]]:
        """
        Verify a backup code and return the hash to remove if valid.
        
        Args:
            stored_hashed_codes: List of stored hashed backup codes
            provided_code: Backup code provided by user
            
        Returns:
            Tuple of (is_valid, hash_to_remove)
        """
        if not provided_code or not stored_hashed_codes:
            return False, None
            
        # Clean and hash the provided code
        clean_code = provided_code.replace('-', '').replace(' ', '').upper()
        if len(clean_code) != 8:
            return False, None
            
        provided_hash = hashlib.sha256(clean_code.encode()).hexdigest()
        
        # Check if hash exists in stored codes
        if provided_hash in stored_hashed_codes:
            return True, provided_hash
            
        return False, None
    
    def is_recently_used_totp(self, token: str, last_used_token: Optional[str]) -> bool:
        """
        Check if TOTP token was recently used to prevent replay attacks.
        
        Args:
            token: Current TOTP token
            last_used_token: Last used TOTP token
            
        Returns:
            True if token was recently used, False otherwise
        """
        return token == last_used_token
    
    def get_current_totp(self, secret: str) -> str:
        """
        Get current TOTP value for testing/debugging purposes.
        
        Args:
            secret: TOTP secret
            
        Returns:
            Current 6-digit TOTP value
        """
        if not secret:
            return ""
            
        totp = pyotp.TOTP(secret)
        return totp.now()


class TwoFactorAuthMixin:
    """
    Mixin for views that require 2FA verification.
    """
    
    def __init__(self):
        super().__init__()
        self.two_factor_auth = TwoFactorAuth()
    
    def verify_2fa_token(self, user, token: str, allow_backup_code: bool = True) -> Tuple[bool, str]:
        """
        Verify 2FA token (TOTP or backup code).
        
        Args:
            user: User instance
            token: Token to verify
            allow_backup_code: Whether to allow backup codes
            
        Returns:
            Tuple of (is_valid, token_type)
        """
        if not user.two_factor_enabled or not token:
            return False, 'disabled'
        
        # Check for replay attack
        if self.two_factor_auth.is_recently_used_totp(token, user.last_totp_used):
            return False, 'replay'
        
        # Try TOTP first
        if self.two_factor_auth.verify_totp(user.two_factor_secret, token):
            # Update last used token
            user.last_totp_used = token
            user.save(update_fields=['last_totp_used'])
            return True, 'totp'
        
        # Try backup code if allowed
        if allow_backup_code and user.backup_codes:
            is_valid, hash_to_remove = self.two_factor_auth.verify_backup_code(
                user.backup_codes, token
            )
            if is_valid:
                # Remove used backup code
                user.backup_codes.remove(hash_to_remove)
                user.save(update_fields=['backup_codes'])
                return True, 'backup'
        
        return False, 'invalid'
    
    def require_2fa_verification(self, user, provided_token: str = None) -> bool:
        """
        Check if 2FA verification is required and valid.
        
        Args:
            user: User instance
            provided_token: 2FA token provided by user
            
        Returns:
            True if 2FA verification passed or not required, False otherwise
        """
        if not user.two_factor_enabled:
            return True
        
        if not provided_token:
            return False
        
        is_valid, _ = self.verify_2fa_token(user, provided_token)
        return is_valid
