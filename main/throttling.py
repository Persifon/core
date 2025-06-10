"""
Custom throttling classes for PersifonPay API endpoints.
"""

from rest_framework.throttling import UserRateThrottle, AnonRateThrottle


class AuthenticationThrottle(AnonRateThrottle):
    """
    Throttle for authentication endpoints (login, register).
    More restrictive to prevent brute force attacks.
    """
    scope = 'auth'


class TransactionThrottle(UserRateThrottle):
    """
    Throttle for transaction endpoints.
    Moderate limits to prevent spam transactions.
    """
    scope = 'transaction'


class RecurringPaymentThrottle(UserRateThrottle):
    """
    Throttle for recurring payment endpoints.
    Lower limits as these are typically set-and-forget operations.
    """
    scope = 'recurring'


class FinancialOperationThrottle(UserRateThrottle):
    """
    Conservative throttle for all financial operations.
    Used for high-risk endpoints.
    """
    scope = 'financial'
    rate = '50/hour'


class TwoFactorThrottle(UserRateThrottle):
    """
    Throttle for two-factor authentication endpoints.
    Moderate limits to prevent abuse while allowing normal usage.
    """
    scope = 'two_factor'


class APIKeyManagementThrottle(UserRateThrottle):
    """
    Throttle for API key management endpoints.
    Conservative limits to prevent API key abuse.
    """
    scope = 'api_key_management'
