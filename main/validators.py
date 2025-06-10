"""
Advanced input validation and sanitization utilities for PersifonPay.
"""

import re
import html
from decimal import Decimal, InvalidOperation
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import datetime


class InputValidator:
    """
    Comprehensive input validation and sanitization.
    """
    
    # Regex patterns for validation
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
    NAME_PATTERN = re.compile(r'^[a-zA-Z\s\'-]{1,50}$')
    
    @staticmethod
    def sanitize_string(value, max_length=255):
        """
        Sanitize string input by escaping HTML and limiting length.
        """
        if not isinstance(value, str):
            return str(value) if value is not None else ""
        
        # Remove leading/trailing whitespace
        value = value.strip()
        
        # Escape HTML characters
        value = html.escape(value)
        
        # Limit length
        if len(value) > max_length:
            value = value[:max_length]
        
        return value
    
    @staticmethod
    def validate_email(email):
        """
        Validate email format.
        """
        if not email or not isinstance(email, str):
            raise ValidationError("Email is required and must be a string.")
        
        email = email.strip().lower()
        if not InputValidator.EMAIL_PATTERN.match(email):
            raise ValidationError("Invalid email format.")
        
        return email
    
    @staticmethod
    def validate_username(username):
        """
        Validate username format.
        """
        if not username or not isinstance(username, str):
            raise ValidationError("Username is required and must be a string.")
        
        username = username.strip()
        if not InputValidator.USERNAME_PATTERN.match(username):
            raise ValidationError(
                "Username must be 3-20 characters long and contain only "
                "letters, numbers, underscores, and hyphens."
            )
        
        return username
    
    @staticmethod
    def validate_name(name, field_name="Name"):
        """
        Validate name fields (first name, last name, etc.).
        """
        if not name or not isinstance(name, str):
            raise ValidationError(f"{field_name} is required and must be a string.")
        
        name = name.strip()
        if not InputValidator.NAME_PATTERN.match(name):
            raise ValidationError(
                f"{field_name} must contain only letters, spaces, apostrophes, "
                "and hyphens, and be 1-50 characters long."
            )
        
        return name
    
    @staticmethod
    def validate_amount(amount, min_amount=0.01, max_amount=1000000):
        """
        Validate monetary amounts.
        """
        if amount is None:
            raise ValidationError("Amount is required.")
        
        try:
            # Convert to Decimal for precise financial calculations
            if isinstance(amount, str):
                amount = Decimal(amount)
            elif isinstance(amount, (int, float)):
                amount = Decimal(str(amount))
            elif not isinstance(amount, Decimal):
                raise ValidationError("Amount must be a valid number.")
            
            # Round to 2 decimal places
            amount = amount.quantize(Decimal('0.01'))
            
            # Validate range
            if amount < Decimal(str(min_amount)):
                raise ValidationError(f"Amount must be at least {min_amount}.")
            
            if amount > Decimal(str(max_amount)):
                raise ValidationError(f"Amount cannot exceed {max_amount}.")
            
            return float(amount)
        
        except (InvalidOperation, ValueError):
            raise ValidationError("Amount must be a valid number.")
    
    @staticmethod
    def validate_password(password):
        """
        Validate password complexity.
        """
        if not password or not isinstance(password, str):
            raise ValidationError("Password is required.")
        
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long.")
        
        if len(password) > 128:
            raise ValidationError("Password cannot exceed 128 characters.")
        
        # Check for at least one uppercase letter
        if not re.search(r'[A-Z]', password):
            raise ValidationError("Password must contain at least one uppercase letter.")
        
        # Check for at least one lowercase letter
        if not re.search(r'[a-z]', password):
            raise ValidationError("Password must contain at least one lowercase letter.")
        
        # Check for at least one digit
        if not re.search(r'\d', password):
            raise ValidationError("Password must contain at least one number.")
        
        # Check for at least one special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError("Password must contain at least one special character.")
        
        return password
    
    @staticmethod
    def validate_recurring_frequency(frequency):
        """
        Validate recurring payment frequency.
        """
        valid_frequencies = ['DAILY', 'WEEKLY', 'MONTHLY', 'YEARLY']
        
        if not frequency or frequency not in valid_frequencies:
            raise ValidationError(
                f"Frequency must be one of: {', '.join(valid_frequencies)}"
            )
        
        return frequency
    
    @staticmethod
    def validate_future_date(date_str, field_name="Date"):
        """
        Validate that a date is in the future.
        """
        if not date_str:
            return None
        
        try:
            if isinstance(date_str, str):
                # Try to parse ISO format
                date_obj = timezone.datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            elif isinstance(date_str, datetime):
                date_obj = date_str
            else:
                raise ValidationError(f"{field_name} must be a valid date string or datetime object.")
            
            # Ensure timezone awareness
            if timezone.is_naive(date_obj):
                date_obj = timezone.make_aware(date_obj)
            
            # Check if date is in the future
            if date_obj <= timezone.now():
                raise ValidationError(f"{field_name} must be in the future.")
            
            return date_obj
        
        except ValueError:
            raise ValidationError(f"{field_name} must be a valid ISO format date.")
    
    @staticmethod
    def validate_totp_token(token):
        """
        Validate TOTP token format (6-digit numeric code).
        
        Args:
            token: TOTP token to validate
            
        Returns:
            bool: True if valid format, False otherwise
        """
        if not token or not isinstance(token, str):
            return False
        
        # Remove any whitespace
        token = token.strip()
        
        # Check if it's exactly 6 digits
        if len(token) != 6:
            return False
        
        # Check if all characters are digits
        if not token.isdigit():
            return False
        
        return True

    @staticmethod
    def validate_backup_code(code):
        """
        Validate backup code format (XXXX-XXXX or 8 alphanumeric characters).
        
        Args:
            code: Backup code to validate
            
        Returns:
            bool: True if valid format, False otherwise
        """
        if not code or not isinstance(code, str):
            return False
        
        # Remove whitespace and convert to uppercase
        code = code.strip().upper()
        
        # Check formatted version (XXXX-XXXX)
        if len(code) == 9 and code[4] == '-':
            parts = code.split('-')
            if len(parts) == 2 and len(parts[0]) == 4 and len(parts[1]) == 4:
                return all(c.isalnum() for c in parts[0] + parts[1])
        
        # Check unformatted version (8 alphanumeric characters)
        if len(code) == 8:
            return code.isalnum()
        
        return False

    @staticmethod
    def validate_ip_address(ip_address):
        """
        Validate an IP address (IPv4 or IPv6).
        
        Args:
            ip_address: IP address string to validate
            
        Raises:
            ValidationError: If IP address is invalid
        """
        import ipaddress
        
        if not ip_address:
            raise ValidationError("IP address is required")
        
        try:
            # This will validate both IPv4 and IPv6 addresses
            ipaddress.ip_address(ip_address)
        except ValueError as exc:
            # Also try to validate as a network (CIDR notation)
            try:
                ipaddress.ip_network(ip_address, strict=False)
            except ValueError:
                raise ValidationError(f"Invalid IP address: {ip_address}") from exc
        
        return ip_address


class SecurityValidator:
    """
    Security-focused validation utilities.
    """
    
    @staticmethod
    def validate_account_access(user, account):
        """
        Validate that a user has access to an account.
        """
        if not account:
            raise ValidationError("Account not found.")
        
        if account.profile != user:
            raise ValidationError("You do not have access to this account.")
        
        return True
    
    @staticmethod
    def validate_transaction_access(user, transaction):
        """
        Validate that a user has access to a transaction.
        """
        if not transaction:
            raise ValidationError("Transaction not found.")
        
        if (transaction.withdraw_account.profile != user and 
            transaction.credit_account.profile != user):
            raise ValidationError("You do not have access to this transaction.")
        
        return True
    
    @staticmethod
    def validate_sufficient_balance(account, amount):
        """
        Validate that an account has sufficient balance for a transaction.
        """
        if account.balance < amount:
            raise ValidationError(
                f"Insufficient balance. Account balance: {account.balance}, "
                f"Required: {amount}"
            )
        
        return True
    
    @staticmethod
    def validate_different_accounts(withdraw_account, credit_account):
        """
        Validate that withdraw and credit accounts are different.
        """
        if withdraw_account.id == credit_account.id:
            raise ValidationError("Cannot transfer to the same account.")
        
        return True


class CustomPasswordValidator:
    """
    Custom password validator that enforces strong password requirements.
    """
    
    def validate(self, password, user=None):
        """
        Validate password according to PersifonPay security requirements.
        """
        # user parameter required by Django's password validator interface
        _ = user  # Acknowledge parameter
        return InputValidator.validate_password(password)
    
    def get_help_text(self):
        return (
            "Your password must contain at least 8 characters, including "
            "at least one uppercase letter, one lowercase letter, one number, "
            "and one special character."
        )
