# secure_views.py - Enhanced views with security features
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.db.models import Q
from django.db import transaction
from rest_framework.response import Response
from rest_framework.request import HttpRequest
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
import json
import math

from .models import Accounts, Transactions, RecurringPayment
from .permissions import AccountAccessMixin, HasAccountAccess, HasTransactionAccess
from .throttling import TransactionThrottle, RecurringPaymentThrottle, FinancialOperationThrottle
from .validators import InputValidator
from .audit import AuditLogger
from .security import SecurityMonitor
from django.conf import settings
from .utils import verify_webhook_signature


class SecureProfileView(APIView, AccountAccessMixin):
    """Enhanced Profile view with security features"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    throttle_classes = [FinancialOperationThrottle]

    def __init__(self):
        super().__init__()
        self.audit_logger = AuditLogger()
        self.security_monitor = SecurityMonitor()
        self.validator = InputValidator()

    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def post(self, request: HttpRequest):
        """Update user profile with enhanced security"""
        try:
            client_ip = self.get_client_ip(request)
            
            # Monitor for suspicious activity
            if self.security_monitor.detect_suspicious_activity(request.user, client_ip):
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='PROFILE_UPDATE_BLOCKED',
                    resource_type='PROFILE',
                    resource_id=str(request.user.id),
                    ip_address=client_ip,
                    severity='WARNING',
                    details={'reason': 'Suspicious activity detected'}
                )
                return Response({'error': 'Request blocked due to suspicious activity'}, 
                              status=status.HTTP_429_TOO_MANY_REQUESTS)

            try:
                data = json.loads(request.body.decode('utf-8'))
            except json.JSONDecodeError:
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='PROFILE_UPDATE_FAILED',
                    resource_type='PROFILE',
                    resource_id=str(request.user.id),
                    ip_address=client_ip,
                    severity='INFO',
                    details={'error': 'Invalid JSON'}
                )
                return JsonResponse({"error": "Invalid JSON"}, status=400)

            # Validate input data
            validation_errors = []
            
            if 'first_name' in data:
                if not self.validator.validate_name(data['first_name']):
                    validation_errors.append('Invalid first name format')
            
            if 'family_name' in data:
                if not self.validator.validate_name(data['family_name']):
                    validation_errors.append('Invalid family name format')
            
            if 'last_name' in data:
                if not self.validator.validate_name(data['last_name']):
                    validation_errors.append('Invalid last name format')

            if validation_errors:
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='PROFILE_UPDATE_FAILED',
                    resource_type='PROFILE',
                    resource_id=str(request.user.id),
                    ip_address=client_ip,
                    severity='INFO',
                    details={'errors': validation_errors}
                )
                return Response({'error': 'Validation failed', 'details': validation_errors}, 
                              status=status.HTTP_400_BAD_REQUEST)

            # Update the user's profile
            user = request.user
            old_values = {
                'first_name': user.first_name,
                'family_name': user.family_name,
                'last_name': user.last_name
            }
            
            user.first_name = data.get("first_name", user.first_name)
            user.family_name = data.get("family_name", user.family_name)
            user.last_name = data.get("last_name", user.last_name)
            user.save()

            # Log successful update
            self.audit_logger.log_user_action(
                user=request.user,
                action='PROFILE_UPDATED',
                resource_type='PROFILE',
                resource_id=str(request.user.id),
                ip_address=client_ip,
                details={
                    'old_values': old_values,
                    'new_values': {
                        'first_name': user.first_name,
                        'family_name': user.family_name,
                        'last_name': user.last_name
                    }
                }
            )
            
            return JsonResponse({
                "message": "Profile updated successfully",
                "profile": {
                    "id": str(user.id),
                    "first_name": user.first_name,
                    "family_name": user.family_name,
                    "last_name": user.last_name
                }
            }, status=200)
            
        except Exception as e:
            self.audit_logger.log_security_event(
                user=request.user,
                action='PROFILE_UPDATE_ERROR',
                resource_type='PROFILE',
                resource_id=str(request.user.id),
                ip_address=self.get_client_ip(request),
                severity='ERROR',
                details={'error': str(e)}
            )
            return JsonResponse({'error': 'Internal server error'}, status=500)

    def get(self, request: HttpRequest):
        """Get user profile with audit logging"""
        try:
            client_ip = self.get_client_ip(request)
            
            # Get all accounts associated with the user
            accounts_data = []
            for account in request.user.accounts.all():
                accounts_data.append({
                    'id': str(account.id),
                    'name': account.name,
                    'balance': account.balance,
                    'public_key': account.public_key
                })
            
            profile_data = {
                'id': str(request.user.id),
                'username': request.user.username,
                'first_name': request.user.first_name or '',
                'family_name': request.user.family_name or '',
                'last_name': request.user.last_name or '',
                'email': request.user.email or '',
                'is_active': request.user.is_active,
                'accounts': accounts_data
            }

            # Log profile access
            self.audit_logger.log_user_action(
                user=request.user,
                action='PROFILE_ACCESSED',
                resource_type='PROFILE',
                resource_id=str(request.user.id),
                ip_address=client_ip,
                details={'accounts_count': len(accounts_data)}
            )
            
            return JsonResponse(profile_data, status=200)
            
        except Exception as e:
            self.audit_logger.log_security_event(
                user=request.user,
                action='PROFILE_ACCESS_ERROR',
                resource_type='PROFILE',
                resource_id=str(request.user.id),
                ip_address=self.get_client_ip(request),
                severity='ERROR',
                details={'error': str(e)}
            )
            return JsonResponse({'error': 'Internal server error'}, status=500)


class SecureAccountView(APIView, AccountAccessMixin):
    """Enhanced Account view with security features"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    throttle_classes = [FinancialOperationThrottle]

    def __init__(self):
        super().__init__()
        self.audit_logger = AuditLogger()
        self.security_monitor = SecurityMonitor()
        self.validator = InputValidator()

    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def get(self, request: HttpRequest):
        """Get all accounts with audit logging"""
        try:
            client_ip = self.get_client_ip(request)
            
            accounts_data = []
            for account in request.user.accounts.all():
                accounts_data.append({
                    'id': str(account.id),
                    'name': account.name,
                    'balance': account.balance,
                    'public_key': account.public_key
                })

            # Log account access
            self.audit_logger.log_user_action(
                user=request.user,
                action='ACCOUNTS_LISTED',
                resource_type='ACCOUNT',
                resource_id='ALL',
                ip_address=client_ip,
                details={'accounts_count': len(accounts_data)}
            )
            
            return Response({'accounts': accounts_data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            self.audit_logger.log_security_event(
                user=request.user,
                action='ACCOUNTS_LIST_ERROR',
                resource_type='ACCOUNT',
                resource_id='ALL',
                ip_address=self.get_client_ip(request),
                severity='ERROR',
                details={'error': str(e)}
            )
            return Response({'error': 'Internal server error'}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request: HttpRequest):
        """Create new account with enhanced validation"""
        try:
            client_ip = self.get_client_ip(request)
            
            # Monitor for suspicious activity
            if self.security_monitor.detect_suspicious_activity(request.user, client_ip):
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='ACCOUNT_CREATE_BLOCKED',
                    resource_type='ACCOUNT',
                    resource_id='NEW',
                    ip_address=client_ip,
                    severity='WARNING',
                    details={'reason': 'Suspicious activity detected'}
                )
                return Response({'error': 'Request blocked due to suspicious activity'}, 
                              status=status.HTTP_429_TOO_MANY_REQUESTS)

            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='ACCOUNT_CREATE_FAILED',
                    resource_type='ACCOUNT',
                    resource_id='NEW',
                    ip_address=client_ip,
                    severity='INFO',
                    details={'error': 'Invalid JSON'}
                )
                return Response({'error': 'Invalid JSON data'}, 
                              status=status.HTTP_400_BAD_REQUEST)
            
            # Validate required fields
            if 'name' not in data:
                return Response({'error': 'Missing required field: name'}, 
                              status=status.HTTP_400_BAD_REQUEST)

            # Validate account name
            if not self.validator.validate_account_name(data['name']):
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='ACCOUNT_CREATE_FAILED',
                    resource_type='ACCOUNT',
                    resource_id='NEW',
                    ip_address=client_ip,
                    severity='INFO',
                    details={'error': 'Invalid account name format'}
                )
                return Response({'error': 'Invalid account name format'}, 
                              status=status.HTTP_400_BAD_REQUEST)

            # Get and validate balance
            balance = data.get('balance', 0.0)
            if not self.validator.validate_amount(balance):
                return Response({'error': 'Invalid balance value'}, 
                              status=status.HTTP_400_BAD_REQUEST)

            # Create new account with atomic transaction
            with transaction.atomic():
                account = Accounts.objects.create(
                    name=data['name'],
                    balance=float(balance)
                )
                
                # Link account to current user's profile
                request.user.accounts.add(account)

            # Log successful account creation
            self.audit_logger.log_financial_transaction(
                user=request.user,
                action='ACCOUNT_CREATED',
                resource_type='ACCOUNT',
                resource_id=str(account.id),
                ip_address=client_ip,
                amount=float(balance),
                details={
                    'account_name': account.name,
                    'initial_balance': float(balance)
                }
            )

            return Response({
                'id': str(account.id),
                'name': account.name,
                'balance': account.balance,
                'message': 'Account created successfully'
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            self.audit_logger.log_security_event(
                user=request.user,
                action='ACCOUNT_CREATE_ERROR',
                resource_type='ACCOUNT',
                resource_id='NEW',
                ip_address=self.get_client_ip(request),
                severity='ERROR',
                details={'error': str(e)}
            )
            return Response({'error': 'Internal server error'}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SecureTransactionView(APIView, AccountAccessMixin):
    """Enhanced Transaction view with security features"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    throttle_classes = [TransactionThrottle]

    def __init__(self):
        super().__init__()
        self.audit_logger = AuditLogger()
        self.security_monitor = SecurityMonitor()
        self.validator = InputValidator()

    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def post(self, request: HttpRequest):
        """Create transaction with enhanced security and validation"""
        try:
            client_ip = self.get_client_ip(request)
            
            # Monitor for suspicious activity
            if self.security_monitor.detect_suspicious_activity(request.user, client_ip):
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='TRANSACTION_BLOCKED',
                    resource_type='TRANSACTION',
                    resource_id='NEW',
                    ip_address=client_ip,
                    severity='WARNING',
                    details={'reason': 'Suspicious activity detected'}
                )
                return Response({'error': 'Request blocked due to suspicious activity'}, 
                              status=status.HTTP_429_TOO_MANY_REQUESTS)

            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='TRANSACTION_FAILED',
                    resource_type='TRANSACTION',
                    resource_id='NEW',
                    ip_address=client_ip,
                    severity='INFO',
                    details={'error': 'Invalid JSON'}
                )
                return Response({'error': 'Invalid JSON data'}, 
                              status=status.HTTP_400_BAD_REQUEST)

            # Validate required fields
            required_fields = ['withdraw_account_id', 'credit_account_id', 'amount', 'message']
            for field in required_fields:
                if field not in data:
                    return Response({'error': f'Missing required field: {field}'},
                                    status=status.HTTP_400_BAD_REQUEST)

            # Validate amount
            if not self.validator.validate_amount(data['amount']):
                return Response({'error': 'Invalid amount format or value'},
                                status=status.HTTP_400_BAD_REQUEST)

            amount = float(data['amount'])

            # Validate account IDs
            if not self.validator.validate_uuid(data['withdraw_account_id']):
                return Response({'error': 'Invalid withdraw account ID format'},
                                status=status.HTTP_400_BAD_REQUEST)
            
            if not self.validator.validate_uuid(data['credit_account_id']):
                return Response({'error': 'Invalid credit account ID format'},
                                status=status.HTTP_400_BAD_REQUEST)

            # Get accounts
            try:
                withdraw_account = get_object_or_404(Accounts, id=data['withdraw_account_id'])
                credit_account = get_object_or_404(Accounts, id=data['credit_account_id'])
            except:
                return Response({'error': 'Account not found'}, 
                              status=status.HTTP_404_NOT_FOUND)

            # Verify user owns the withdraw account
            if not request.user.accounts.filter(id=withdraw_account.id).exists():
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='UNAUTHORIZED_TRANSACTION_ATTEMPT',
                    resource_type='TRANSACTION',
                    resource_id='NEW',
                    ip_address=client_ip,
                    severity='WARNING',
                    details={
                        'withdraw_account_id': str(withdraw_account.id),
                        'attempted_amount': amount
                    }
                )
                return Response({'error': 'You do not have permission to withdraw from this account'},
                                status=status.HTTP_403_FORBIDDEN)

            # Check sufficient balance
            rounded_balance = math.ceil(withdraw_account.balance * 100) / 100
            if rounded_balance < amount:
                self.audit_logger.log_financial_transaction(
                    user=request.user,
                    action='TRANSACTION_DECLINED_INSUFFICIENT_FUNDS',
                    resource_type='TRANSACTION',
                    resource_id='NEW',
                    ip_address=client_ip,
                    amount=amount,
                    details={
                        'withdraw_account_id': str(withdraw_account.id),
                        'current_balance': rounded_balance,
                        'requested_amount': amount
                    }
                )
                return Response({
                    'error': 'Insufficient balance in the withdraw account',
                    'current_balance': rounded_balance,
                    'requested_amount': amount
                }, status=status.HTTP_400_BAD_REQUEST)

            # Create transaction with atomic operation
            with transaction.atomic():
                # Create transaction record
                new_transaction = Transactions(
                    withdraw_account=withdraw_account,
                    credit_account=credit_account,
                    amount=amount,
                    message=data['message']
                )
                new_transaction.save()

                # Update account balances with precision handling
                withdraw_account.balance = math.ceil((withdraw_account.balance - amount) * 100) / 100
                credit_account.balance = math.ceil((credit_account.balance + amount) * 100) / 100
                
                withdraw_account.save()
                credit_account.save()

            # Log successful transaction
            self.audit_logger.log_financial_transaction(
                user=request.user,
                action='TRANSACTION_COMPLETED',
                resource_type='TRANSACTION',
                resource_id=str(new_transaction.id),
                ip_address=client_ip,
                amount=amount,
                details={
                    'withdraw_account_id': str(withdraw_account.id),
                    'credit_account_id': str(credit_account.id),
                    'message': data['message'],
                    'new_withdraw_balance': withdraw_account.balance,
                    'new_credit_balance': credit_account.balance
                }
            )

            transaction_data = {
                'id': str(new_transaction.id),
                'withdraw_account': str(new_transaction.withdraw_account.id),
                'amount': new_transaction.amount,
                'credit_account': str(new_transaction.credit_account.id),
                'message': new_transaction.message,
                'date': new_transaction.date.isoformat() if new_transaction.date else None,
            }
            
            return Response(transaction_data, status=status.HTTP_201_CREATED)

        except Exception as e:
            self.audit_logger.log_security_event(
                user=request.user,
                action='TRANSACTION_ERROR',
                resource_type='TRANSACTION',
                resource_id='NEW',
                ip_address=self.get_client_ip(request),
                severity='ERROR',
                details={'error': str(e)}
            )
            return Response({'error': 'Internal server error'}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, transaction_id: str):
        """Get transaction details with audit logging"""
        try:
            client_ip = self.get_client_ip(request)
            
            # Validate transaction ID format
            if not self.validator.validate_uuid(transaction_id):
                return Response({'error': 'Invalid transaction ID format'},
                              status=status.HTTP_400_BAD_REQUEST)

            transaction_obj = get_object_or_404(Transactions, id=transaction_id)
            
            # Check if user has access to the transaction
            if not self.check_transaction_access(request.user, transaction_obj):
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='UNAUTHORIZED_TRANSACTION_ACCESS',
                    resource_type='TRANSACTION',
                    resource_id=transaction_id,
                    ip_address=client_ip,
                    severity='WARNING',
                    details={'transaction_id': transaction_id}
                )
                return Response(
                    {"detail": "You don't have access to this transaction."},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Log transaction access
            self.audit_logger.log_user_action(
                user=request.user,
                action='TRANSACTION_VIEWED',
                resource_type='TRANSACTION',
                resource_id=transaction_id,
                ip_address=client_ip,
                details={'amount': transaction_obj.amount}
            )
            
            transaction_data = {
                'id': str(transaction_obj.id),
                'withdraw_account': str(transaction_obj.withdraw_account.id),
                'amount': transaction_obj.amount,
                'credit_account': str(transaction_obj.credit_account.id),
                'message': transaction_obj.message,
                'date': str(transaction_obj.date) if transaction_obj.date else None,
            }
            return Response(transaction_data)
            
        except Transactions.DoesNotExist:
            return Response(
                {"detail": "Transaction not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            self.audit_logger.log_security_event(
                user=request.user,
                action='TRANSACTION_ACCESS_ERROR',
                resource_type='TRANSACTION',
                resource_id=transaction_id,
                ip_address=self.get_client_ip(request),
                severity='ERROR',
                details={'error': str(e)}
            )
            return Response({'error': 'Internal server error'}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SecureGetTransactionsView(APIView, AccountAccessMixin):
    """Enhanced transactions list view with security features"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, HasAccountAccess]
    throttle_classes = [TransactionThrottle]

    def __init__(self):
        super().__init__()
        self.audit_logger = AuditLogger()
        self.security_monitor = SecurityMonitor()
        self.validator = InputValidator()

    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def get(self, request: HttpRequest, account_id: str):
        """Get transactions for an account with enhanced security and audit logging"""
        try:
            client_ip = self.get_client_ip(request)
            
            # Validate account ID format
            if not self.validator.validate_uuid(account_id):
                return Response({'error': 'Invalid account ID format'},
                              status=status.HTTP_400_BAD_REQUEST)

            # Check if user has access to this account
            account = self.check_account_access(request.user, account_id)
            if not account:
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='UNAUTHORIZED_TRANSACTIONS_ACCESS',
                    resource_type='TRANSACTION',
                    resource_id=account_id,
                    ip_address=client_ip,
                    severity='WARNING',
                    details={'account_id': account_id}
                )
                return Response(
                    {"detail": "Account not found or you don't have access to it."},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Fetch transactions related to the specified account
            transactions = Transactions.objects.filter(
                Q(withdraw_account_id=account_id) | Q(credit_account_id=account_id)
            ).select_related('withdraw_account', 'credit_account').order_by('-date')

            # Serialize the transactions
            transaction_list = []
            for transaction in transactions:
                transaction_list.append({
                    'id': str(transaction.id),
                    'withdraw_account': str(transaction.withdraw_account.id),
                    'amount': transaction.amount,
                    'credit_account': str(transaction.credit_account.id),
                    'message': transaction.message,
                    'date': str(transaction.date),
                })

            # Log transactions access
            self.audit_logger.log_user_action(
                user=request.user,
                action='TRANSACTIONS_ACCESSED',
                resource_type='TRANSACTION',
                resource_id=account_id,
                ip_address=client_ip,
                details={
                    'account_id': account_id,
                    'transactions_count': len(transaction_list)
                }
            )

            return Response({
                'account_id': account_id,
                'account_name': account.name,
                'transactions': transaction_list
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            self.audit_logger.log_security_event(
                user=request.user,
                action='TRANSACTIONS_ACCESS_ERROR',
                resource_type='TRANSACTION',
                resource_id=account_id,
                ip_address=self.get_client_ip(request),
                severity='ERROR',
                details={'error': str(e)}
            )
            return Response(
                {"detail": f"Error retrieving transactions: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SecureAccountDetailView(APIView, AccountAccessMixin):
    """Enhanced individual account operations with security"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, HasAccountAccess]
    throttle_classes = [FinancialOperationThrottle]

    def __init__(self):
        super().__init__()
        self.audit_logger = AuditLogger()
        self.security_monitor = SecurityMonitor()
        self.validator = InputValidator()

    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def get(self, request: HttpRequest, account_id: str):
        """Get details of a specific account with audit logging"""
        try:
            client_ip = self.get_client_ip(request)
            
            # Validate account ID format
            if not self.validator.validate_uuid(account_id):
                return Response({'error': 'Invalid account ID format'},
                              status=status.HTTP_400_BAD_REQUEST)

            account = self.check_account_access(request.user, account_id)
            if not account:
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='UNAUTHORIZED_ACCOUNT_ACCESS',
                    resource_type='ACCOUNT',
                    resource_id=account_id,
                    ip_address=client_ip,
                    severity='WARNING',
                    details={'account_id': account_id}
                )
                return Response(
                    {"detail": "Account not found or you don't have access to it."},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Log account access
            self.audit_logger.log_user_action(
                user=request.user,
                action='ACCOUNT_VIEWED',
                resource_type='ACCOUNT',
                resource_id=account_id,
                ip_address=client_ip,
                details={'account_name': account.name, 'balance': account.balance}
            )
        
            return Response({
                'id': str(account.id),
                'name': account.name,
                'balance': account.balance,
                'public_key': account.public_key
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            self.audit_logger.log_security_event(
                user=request.user,
                action='ACCOUNT_ACCESS_ERROR',
                resource_type='ACCOUNT',
                resource_id=account_id,
                ip_address=self.get_client_ip(request),
                severity='ERROR',
                details={'error': str(e)}
            )
            return Response({'error': 'Internal server error'}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request: HttpRequest, account_id: str):
        """Update account details with enhanced security"""
        try:
            client_ip = self.get_client_ip(request)
            
            # Monitor for suspicious activity
            if self.security_monitor.detect_suspicious_activity(request.user, client_ip):
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='ACCOUNT_UPDATE_BLOCKED',
                    resource_type='ACCOUNT',
                    resource_id=account_id,
                    ip_address=client_ip,
                    severity='WARNING',
                    details={'reason': 'Suspicious activity detected'}
                )
                return Response({'error': 'Request blocked due to suspicious activity'}, 
                              status=status.HTTP_429_TOO_MANY_REQUESTS)

            # Validate account ID format
            if not self.validator.validate_uuid(account_id):
                return Response({'error': 'Invalid account ID format'},
                              status=status.HTTP_400_BAD_REQUEST)

            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                return Response({'error': 'Invalid JSON data'}, 
                              status=status.HTTP_400_BAD_REQUEST)
            
            # Check if user has access to this account
            account = self.check_account_access(request.user, account_id)
            if not account:
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='UNAUTHORIZED_ACCOUNT_UPDATE',
                    resource_type='ACCOUNT',
                    resource_id=account_id,
                    ip_address=client_ip,
                    severity='WARNING',
                    details={'account_id': account_id}
                )
                return Response(
                    {"detail": "Account not found or you don't have access to it."},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Store old values for audit log
            old_values = {
                'name': account.name,
                'balance': account.balance
            }
            
            # Update account fields if provided with validation
            updated = False
            if 'name' in data:
                if not self.validator.validate_account_name(data['name']):
                    return Response({'error': 'Invalid account name format'}, 
                                  status=status.HTTP_400_BAD_REQUEST)
                account.name = data['name']
                updated = True
                
            if 'balance' in data:
                if not self.validator.validate_amount(data['balance']):
                    return Response({'error': 'Invalid balance value'}, 
                                  status=status.HTTP_400_BAD_REQUEST)
                account.balance = float(data['balance'])
                updated = True
            
            if updated:
                with transaction.atomic():
                    account.save()

                # Log successful update
                self.audit_logger.log_financial_transaction(
                    user=request.user,
                    action='ACCOUNT_UPDATED',
                    resource_type='ACCOUNT',
                    resource_id=account_id,
                    ip_address=client_ip,
                    amount=account.balance,
                    details={
                        'old_values': old_values,
                        'new_values': {
                            'name': account.name,
                            'balance': account.balance
                        }
                    }
                )
            
            return Response({
                'id': str(account.id),
                'name': account.name,
                'balance': account.balance,
                'public_key': account.public_key,
                'message': 'Account updated successfully' if updated else 'No changes made'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            self.audit_logger.log_security_event(
                user=request.user,
                action='ACCOUNT_UPDATE_ERROR',
                resource_type='ACCOUNT',
                resource_id=account_id,
                ip_address=self.get_client_ip(request),
                severity='ERROR',
                details={'error': str(e)}
            )
            return Response({'error': 'Internal server error'}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request: HttpRequest, account_id: str):
        """Delete an account with enhanced security and audit logging"""
        try:
            client_ip = self.get_client_ip(request)
            
            # Monitor for suspicious activity
            if self.security_monitor.detect_suspicious_activity(request.user, client_ip):
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='ACCOUNT_DELETE_BLOCKED',
                    resource_type='ACCOUNT',
                    resource_id=account_id,
                    ip_address=client_ip,
                    severity='WARNING',
                    details={'reason': 'Suspicious activity detected'}
                )
                return Response({'error': 'Request blocked due to suspicious activity'}, 
                              status=status.HTTP_429_TOO_MANY_REQUESTS)

            # Validate account ID format
            if not self.validator.validate_uuid(account_id):
                return Response({'error': 'Invalid account ID format'},
                              status=status.HTTP_400_BAD_REQUEST)

            # Check if user has access to this account
            account = self.check_account_access(request.user, account_id)
            if not account:
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='UNAUTHORIZED_ACCOUNT_DELETE',
                    resource_type='ACCOUNT',
                    resource_id=account_id,
                    ip_address=client_ip,
                    severity='WARNING',
                    details={'account_id': account_id}
                )
                return Response(
                    {"detail": "Account not found or you don't have access to it."},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Check if account has any pending transactions (optional safety check)
            has_transactions = Transactions.objects.filter(
                Q(withdraw_account=account) | Q(credit_account=account)
            ).exists()
            
            force_delete = request.GET.get('force_delete', 'false').lower() == 'true'
            
            if has_transactions and not force_delete:
                transaction_count = Transactions.objects.filter(
                    Q(withdraw_account=account) | Q(credit_account=account)
                ).count()
                
                return Response({
                    'error': 'Account has transaction history. Use ?force_delete=true to proceed.',
                    'transaction_count': transaction_count
                }, status=status.HTTP_400_BAD_REQUEST)

            # Store account details for audit log before deletion
            account_details = {
                'name': account.name,
                'balance': account.balance,
                'transaction_count': Transactions.objects.filter(
                    Q(withdraw_account=account) | Q(credit_account=account)
                ).count()
            }
            
            account_name = account.name
            
            # Delete the account
            with transaction.atomic():
                account.delete()

            # Log successful deletion
            self.audit_logger.log_financial_transaction(
                user=request.user,
                action='ACCOUNT_DELETED',
                resource_type='ACCOUNT',
                resource_id=account_id,
                ip_address=client_ip,
                amount=account_details['balance'],
                details=account_details
            )
            
            return Response({
                'message': f'Account "{account_name}" (ID: {account_id}) successfully deleted'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            self.audit_logger.log_security_event(
                user=request.user,
                action='ACCOUNT_DELETE_ERROR',
                resource_type='ACCOUNT',
                resource_id=account_id,
                ip_address=self.get_client_ip(request),
                severity='ERROR',
                details={'error': str(e)}
            )
            return Response({'error': 'Internal server error'}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class WebhookReceiveView(APIView):
    """
    Sample webhook endpoint with HMAC signature verification.
    Expects header: X-Signature (hex), body: raw JSON, secret from settings.WEBHOOK_SECRET
    """
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        signature = request.headers.get('X-Signature')
        secret = getattr(settings, 'WEBHOOK_SECRET', None)
        if not secret:
            return Response({'error': 'Webhook secret not configured'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        if not signature:
            return Response({'error': 'Missing X-Signature header'}, status=status.HTTP_400_BAD_REQUEST)
        if not verify_webhook_signature(request.body, signature, secret):
            return Response({'error': 'Invalid signature'}, status=status.HTTP_400_BAD_REQUEST)
        # Process webhook payload (example: just echo back)
        return Response({'message': 'Webhook received and verified', 'data': request.data}, status=status.HTTP_200_OK)
