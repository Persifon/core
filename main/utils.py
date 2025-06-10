"""
Common utility functions for PersifonPay.
"""

import hmac
import hashlib
from django.conf import settings


def get_client_ip(request) -> str:
    """
    Extract client IP address from Django request.
    
    Args:
        request: Django HttpRequest object
        
    Returns:
        str: Client IP address
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Take the first IP in the chain
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    
    return ip or '127.0.0.1'  # Fallback for local development


def format_currency(amount: float, currency: str = 'USD') -> str:
    """
    Format amount as currency string.
    
    Args:
        amount: Decimal or float amount
        currency: Currency code (default: USD)
        
    Returns:
        str: Formatted currency string
    """
    if not isinstance(amount, (int, float)):
        raise ValueError('Amount must be a number')
    return f"{currency} {amount:.2f}"


def truncate_string(text: str, max_length: int = 50, suffix: str = '...') -> str:
    """
    Truncate string to maximum length with optional suffix.
    
    Args:
        text: String to truncate
        max_length: Maximum length (default: 50)
        suffix: Suffix to add if truncated (default: '...')
        
    Returns:
        str: Truncated string
    """
    if not isinstance(text, str):
        return ''
    if not text or len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def safe_get_value(dictionary: dict, key, default=None):
    """
    Safely get value from dictionary with type checking.
    
    Args:
        dictionary: Dictionary to get value from
        key: Key to look up
        default: Default value if key not found
        
    Returns:
        Value from dictionary or default
    """
    if not isinstance(dictionary, dict):
        return default
    
    return dictionary.get(key, default)


def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    """
    Verify HMAC-SHA256 signature for webhook payloads.
    
    Args:
        payload: Raw request body (bytes)
        signature: Signature from header (hex string)
        secret: Shared secret (string)
        
    Returns:
        True if valid, False otherwise
    """
    try:
        int(signature, 16)
    except (ValueError, TypeError):
        return False
    computed = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, signature)
