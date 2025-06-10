# urls.py
from django.urls import path
from main.secure_views import (
    SecureProfileView, 
    SecureAccountView, 
    SecureTransactionView,
    SecureGetTransactionsView,
    SecureAccountDetailView,
    WebhookReceiveView
)
from main.secure_recurring_views import SecureRecurringPaymentView, SecureRecurringPaymentDetailView
from main.two_factor_views import (
    TwoFactorSetupView,
    TwoFactorVerifySetupView,
    TwoFactorDisableView,
    TwoFactorStatusView,
    TwoFactorBackupCodesView,
    TwoFactorVerifyView
)
from main.api_key_views import (
    APIKeyManagementView,
    APIKeyDetailView,
    api_key_scopes,
    api_key_usage_stats
)
from main.views_pos import POSAcquiringView # Added import for POSAcquiringView
from main.views import health_check # Import health_check view
# from main.debug_auth import DebugTokenView

urlpatterns = [
    # Enhanced secure endpoints
    path('api/profile/', SecureProfileView.as_view()),
    path('api/account/', SecureAccountView.as_view()),
    path('api/account/<str:account_id>/', SecureAccountDetailView.as_view()),
    path('api/transactions/<str:account_id>/', SecureGetTransactionsView.as_view()),
    path('api/transaction/', SecureTransactionView.as_view()),
    path('api/transaction/<str:transaction_id>/', SecureTransactionView.as_view()),
    path('api/recurring-payments/', SecureRecurringPaymentView.as_view()),
    path('api/recurring-payments/<str:payment_id>/', SecureRecurringPaymentDetailView.as_view()),
    
    # Two-Factor Authentication endpoints
    path('api/2fa/setup/', TwoFactorSetupView.as_view(), name='api/2fa/setup/'),
    path('api/2fa/verify-setup/', TwoFactorVerifySetupView.as_view(), name='api/2fa/verify-setup/'),
    path('api/2fa/disable/', TwoFactorDisableView.as_view(), name='api/2fa/disable/'),
    path('api/2fa/status/', TwoFactorStatusView.as_view(), name='api/2fa/status/'),
    path('api/2fa/backup-codes/', TwoFactorBackupCodesView.as_view(), name='api/2fa/backup-codes/'),
    path('api/2fa/verify/', TwoFactorVerifyView.as_view(), name='api/2fa/verify/'),
    
    # API Key Management endpoints
    path('api/api-keys/', APIKeyManagementView.as_view(), name='api_key_management'),
    path('api/api-keys/scopes/', api_key_scopes, name='api_key_scopes'),
    path('api/api-keys/<str:api_key_id>/', APIKeyDetailView.as_view(), name='api_key_detail'),
    path('api/api-keys/<str:api_key_id>/usage/', api_key_usage_stats, name='api_key_usage_stats'),
    
    # path('api/debug-token/', DebugTokenView.as_view()),  # Debug endpoint for authentication
    path('api/webhook/receive/', WebhookReceiveView.as_view(), name='webhook-receive'),

    # POS Endpoints
    path('api/pos/acquire/', POSAcquiringView.as_view(), name='pos-acquire-transaction'), # Added POS acquiring endpoint

    # Health check endpoint
    path('health/', health_check, name='health_check'),
]
