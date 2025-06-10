# permissions.py
from rest_framework.permissions import BasePermission
from .models import Accounts, Transactions, POSTerminal
from .api_key_middleware import APIKeyUser


class AccountAccessMixin:
    """
    Mixin to provide account access control methods.
    """
    
    def check_account_access(self, user, account_id):
        """
        Check if a user has access to a specific account.
        Returns the account if access is granted, None if not.
        """
        try:
            account = Accounts.objects.get(id=account_id)
            if user.accounts.filter(id=account_id).exists():
                return account
            return None
        except Accounts.DoesNotExist:
            return None
    
    def check_transaction_access(self, user, transaction):
        """
        Check if a user has access to view/modify a transaction.
        User must have access to at least one of the accounts involved.
        """
        withdraw_access = user.accounts.filter(id=transaction.withdraw_account.id).exists()
        credit_access = user.accounts.filter(id=transaction.credit_account.id).exists()
        return withdraw_access or credit_access
    
    def get_user_accounts(self, user):
        """
        Get all accounts associated with the user.
        """
        return user.accounts.all()


class HasAccountAccess(BasePermission):
    """
    Permission to check if user has access to a specific account.
    """
    message = "You don't have access to this account."
    
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        
        # Get account_id from URL parameters or request data
        account_id = view.kwargs.get('account_id')
        if not account_id and hasattr(view, 'get_account_id'):
            account_id = view.get_account_id(request)
        
        if not account_id:
            return True  # Let the view handle missing account_id
        
        # Check if user has access to the account
        try:
            account = Accounts.objects.get(id=account_id)
            return request.user.accounts.filter(id=account_id).exists()
        except Accounts.DoesNotExist:
            return False


class HasTransactionAccess(BasePermission):
    """
    Permission to check if user has access to a specific transaction.
    """
    message = "You don't have access to this transaction."
    
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        
        # Get transaction_id from URL parameters
        transaction_id = view.kwargs.get('transaction_id')
        if not transaction_id:
            return True  # Let the view handle missing transaction_id
        
        try:
            transaction = Transactions.objects.get(id=transaction_id)
            # User has access if they own either the withdraw or credit account
            withdraw_access = request.user.accounts.filter(id=transaction.withdraw_account.id).exists()
            credit_access = request.user.accounts.filter(id=transaction.credit_account.id).exists()
            return withdraw_access or credit_access
        except Transactions.DoesNotExist:
            return False


class IsPOSTerminal(BasePermission):
    """
    Permission to check if the request is from an authenticated POS terminal.
    Ensures that the API key used is linked to an active POSTerminal.
    """
    message = "Invalid or unauthorized POS terminal."

    def has_permission(self, request, view):
        # Ensure the user is authenticated via APIKeyUser (set by APIKeyAuthenticationMiddleware)
        if not hasattr(request, 'user') or not isinstance(request.user, APIKeyUser):
            self.message = "API key authentication required."
            return False
        
        # Ensure api_key object is attached to the request (set by APIKeyAuthenticationMiddleware)
        if not hasattr(request, 'api_key') or not request.api_key:
            self.message = "API key not found in request."
            return False

        api_key_instance = request.api_key
        
        try:
            # Check if the APIKey is associated with an active POSTerminal
            # Assuming POSTerminal has a ForeignKey or OneToOneField named 'api_key' to the APIKey model
            pos_terminal = POSTerminal.objects.get(api_key=api_key_instance, is_active=True)
            
            # Store the terminal on the request for easy access in the view
            request.pos_terminal = pos_terminal 
            return True
        except POSTerminal.DoesNotExist:
            self.message = "API key is not associated with an active POS terminal."
            return False
        except Exception: # pylint: disable=broad-except
            # Log the exception details here in a real application
            self.message = "An error occurred while verifying POS terminal. Please contact support."
            return False
