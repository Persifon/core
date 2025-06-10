# views.py
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.db.models import Q
from rest_framework.response import Response
from rest_framework.request import HttpRequest
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
import json
import math

from .models import Accounts, Transactions, RecurringPayment, RecurringPayment
from .permissions import AccountAccessMixin, HasAccountAccess, HasTransactionAccess


def health_check(request):
    """
    A simple health check endpoint that returns a 200 OK response.
    """
    return JsonResponse({'status': 'ok', 'message': 'System is healthy.'}, status=200)


class ProfileView(APIView, AccountAccessMixin):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request: HttpRequest):
        try:
            data = json.loads(request.body.decode('utf-8'))
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        # Update the current user's profile (since we're using Profile as the User model)
        user = request.user
        user.first_name = data.get("first_name", user.first_name)
        user.family_name = data.get("family_name", user.family_name)
        user.last_name = data.get("last_name", user.last_name)
        user.save()
        
        return JsonResponse({
            "message": "ok",
            "profile": {
                "id": str(user.id),
                "first_name": user.first_name,
                "family_name": user.family_name,
                "last_name": user.last_name
            }
        }, status=200)
    
    def get(self, request: HttpRequest):
        # Since we're using authentication, we can just use request.user directly
        # No need to query for the profile since the user IS the profile
        try:
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
            return JsonResponse(profile_data, status=200)
        except AttributeError:
            # This happens if a field doesn't exist
            return JsonResponse({'error': 'Profile information incomplete'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)


class AccountView(APIView, AccountAccessMixin):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request: HttpRequest):
        """Get all accounts associated with the current user"""
        try:
            accounts_data = []
            for account in request.user.accounts.all():
                accounts_data.append({
                    'id': str(account.id),
                    'name': account.name,
                    'balance': account.balance,
                    'public_key': account.public_key
                })
            
            return Response({
                'accounts': accounts_data
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({'error': str(e)}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request: HttpRequest):
        try:
            data = json.loads(request.body)
            
            # Validate required fields
            if 'name' not in data:
                return Response({'error': 'Missing required field: name'}, 
                              status=status.HTTP_400_BAD_REQUEST)

            # Get balance with default value
            balance = data.get('balance', 0.0)
            try:
                balance = float(balance)
            except ValueError:
                return Response({'error': 'Invalid balance value'}, 
                              status=status.HTTP_400_BAD_REQUEST)

            # Create new account
            account = Accounts.objects.create(
                name=data['name'],
                balance=balance
            )

            # Link account to current user's profile
            request.user.accounts.add(account)

            return Response({
                'id': str(account.id),
                'name': account.name,
                'balance': account.balance
            }, status=status.HTTP_201_CREATED)

        except json.JSONDecodeError:
            return Response({'error': 'Invalid JSON data'}, 
                          status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request: HttpRequest):
        """Update account details - only if user has access to the account"""
        try:
            data = json.loads(request.body)
            
            if 'account_id' not in data:
                return Response({'error': 'Missing required field: account_id'}, 
                              status=status.HTTP_400_BAD_REQUEST)
            
            # Check if user has access to this account
            account = self.check_account_access(request.user, data['account_id'])
            if not account:
                return Response(
                    {"error": "Account not found or you don't have access to it."},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Update account fields if provided
            if 'name' in data:
                account.name = data['name']
            if 'balance' in data:
                try:
                    account.balance = float(data['balance'])
                except ValueError:
                    return Response({'error': 'Invalid balance value'}, 
                                  status=status.HTTP_400_BAD_REQUEST)
            
            account.save()
            
            return Response({
                'id': str(account.id),
                'name': account.name,
                'balance': account.balance,
                'public_key': account.public_key
            }, status=status.HTTP_200_OK)

        except json.JSONDecodeError:
            return Response({'error': 'Invalid JSON data'}, 
                          status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request: HttpRequest):
        """Delete an account - only if user has access to the account"""
        try:
            data = json.loads(request.body)
            
            if 'account_id' not in data:
                return Response({'error': 'Missing required field: account_id'}, 
                              status=status.HTTP_400_BAD_REQUEST)
            
            # Check if user has access to this account
            account = self.check_account_access(request.user, data['account_id'])
            if not account:
                return Response(
                    {"error": "Account not found or you don't have access to it."},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Check if account has any pending transactions (optional safety check)
            has_transactions = Transactions.objects.filter(
                Q(withdraw_account=account) | Q(credit_account=account)
            ).exists()
            
            if has_transactions and not data.get('force_delete', False):
                return Response({
                    'error': 'Account has transaction history. Use force_delete=true to proceed.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            account_id = str(account.id)
            account.delete()
            
            return Response({
                'message': f'Account {account_id} successfully deleted'
            }, status=status.HTTP_200_OK)

        except json.JSONDecodeError:
            return Response({'error': 'Invalid JSON data'}, 
                          status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetTransactionsView(APIView, AccountAccessMixin):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, HasAccountAccess]
    
    def get(self, request: HttpRequest, account_id: str):
        """Get transactions for an account - only if user has access to the account"""
        try:
            # Check if user has access to this account using our helper function
            account = self.check_account_access(request.user, account_id)
            if not account:
                return Response(
                    {"error": "Account not found or you don't have access to it."},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Fetch transactions related to the specified account
            transactions = Transactions.objects.filter(
                Q(withdraw_account_id=account_id) | Q(credit_account_id=account_id)
            ).select_related('withdraw_account', 'credit_account').order_by('-date')

            # Serialize the transactions
            transaction_list = [
                {
                    'id': str(transaction.id),
                    'withdraw_account': str(transaction.withdraw_account.id),
                    'amount': transaction.amount,
                    'credit_account': str(transaction.credit_account.id),
                    'message': transaction.message,
                    'date': str(transaction.date),
                }
                for transaction in transactions
            ]

            return Response({
                'account_id': account_id,
                'account_name': account.name,
                'transactions': transaction_list
            })
            
        except Exception as e:
            return Response(
                {"error": f"Error retrieving transactions: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )




class TransactionView(APIView, AccountAccessMixin):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, HasTransactionAccess]

    def get(self, request, transaction_id: str):
        try:
            transaction = get_object_or_404(Transactions, id=transaction_id)
            
            # Check if user has access to at least one of the accounts involved in the transaction
            if not self.check_transaction_access(request.user, transaction):
                return Response(
                    {"error": "You don't have access to this transaction."},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            transaction_data = {
                'id': str(transaction.id),
                'withdraw_account': str(transaction.withdraw_account.id),
                'amount': transaction.amount,
                'credit_account': str(transaction.credit_account.id),
                'message': transaction.message,
                'date': str(transaction.date) if transaction.date else None,
            }
            return Response(transaction_data)
        except Transactions.DoesNotExist:
            return Response(
                {"error": "Transaction not found."},
                status=status.HTTP_404_NOT_FOUND
            )

    def put(self, request):
        try:
            data = json.loads(request.body)
            required_fields = ['withdraw_account_id', 'credit_account_id', 'amount', 'message']
            for field in required_fields:
                if field not in data:
                    return Response({'error': f'Missing required field: {field}'},
                                    status=status.HTTP_400_BAD_REQUEST)

            # Validate amount
            try:
                amount = float(data['amount'])
                if amount <= 0:
                    return Response({'error': 'Amount must be positive'},
                                    status=status.HTTP_400_BAD_REQUEST)
            except (ValueError, TypeError):
                return Response({'error': 'Invalid amount format'},
                                status=status.HTTP_400_BAD_REQUEST)

            withdraw_account = get_object_or_404(Accounts, id=data['withdraw_account_id'])
            credit_account = get_object_or_404(Accounts, id=data['credit_account_id'])

            # Verify that the user owns the withdraw account
            if not request.user.accounts.filter(id=withdraw_account.id).exists():
                return Response({'error': 'You do not have permission to withdraw from this account'},
                                status=status.HTTP_403_FORBIDDEN)

            # Check for sufficient balance
            if withdraw_account.balance < amount:
                return Response({
                    'error': 'Insufficient balance in the withdraw account',
                    'current_balance': withdraw_account.balance,
                    'requested_amount': amount
                }, status=status.HTTP_400_BAD_REQUEST)

            # Create and save the transaction
            transaction = Transactions(
                withdraw_account=withdraw_account,
                credit_account=credit_account,
                amount=amount,
                message=data['message']
            )
            transaction.save()

            # Update account balances
            withdraw_account.balance -= amount
            credit_account.balance += amount
            withdraw_account.save()
            credit_account.save()

            transaction_data = {
                'id': str(transaction.id),
                'withdraw_account': str(transaction.withdraw_account.pk),
                'amount': transaction.amount,
                'credit_account': str(transaction.credit_account.pk),
                'message': transaction.message,
                'date': str(transaction.date) if transaction.date else None,
            }
            return Response(transaction_data, status=status.HTTP_200_OK)
        except json.JSONDecodeError:
            return Response({'error': 'Invalid JSON data'}, status=status.HTTP_400_BAD_REQUEST)
        except Accounts.DoesNotExist:
            return Response({'error': 'Account not found'}, status=status.HTTP_404_NOT_FOUND)
        except Transactions.DoesNotExist:
            return Response({'error': 'Transaction not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Unexpected error: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CreateTransactionView(APIView, AccountAccessMixin):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            data = json.loads(request.body)
            required_fields = ['withdraw_account_id', 'credit_account_id', 'amount', 'message']
            for field in required_fields:
                if field not in data:
                    return Response({'error': f'Missing required field: {field}'},
                                    status=status.HTTP_400_BAD_REQUEST)

            # Validate amount
            try:
                amount = float(data['amount'])
                if amount <= 0:
                    return Response({'error': 'Amount must be positive'},
                                    status=status.HTTP_400_BAD_REQUEST)
            except (ValueError, TypeError):
                return Response({'error': 'Invalid amount format'},
                                status=status.HTTP_400_BAD_REQUEST)

            withdraw_account = get_object_or_404(Accounts, id=data['withdraw_account_id'])
            credit_account = get_object_or_404(Accounts, id=data['credit_account_id'])

            # Verify that the user owns the withdraw account
            if not request.user.accounts.filter(id=withdraw_account.id).exists():
                return Response({'error': 'You do not have permission to withdraw from this account'},
                                status=status.HTTP_403_FORBIDDEN)

            # Check for sufficient balance with exact amount validation
            rounded_balance = math.ceil(withdraw_account.balance * 100) / 100
            if rounded_balance < amount:
                return Response({
                    'error': 'Insufficient balance in the withdraw account',
                    'current_balance': rounded_balance,
                    'requested_amount': amount
                }, status=status.HTTP_400_BAD_REQUEST)

            transaction = Transactions(
                withdraw_account=withdraw_account,
                credit_account=credit_account,
                amount=amount,
                message=data['message']
            )
            transaction.save()

            withdraw_account.balance = math.ceil((withdraw_account.balance - amount) * 100) / 100
            credit_account.balance = math.ceil((credit_account.balance + amount) * 100) / 100
            withdraw_account.save()
            credit_account.save()

            transaction_data = {
                'id': str(transaction.id),
                'withdraw_account': str(transaction.withdraw_account.id),
                'amount': transaction.amount,
                'credit_account': str(transaction.credit_account.id),
                'message': transaction.message,
                'date': transaction.date.isoformat() if transaction.date else None,
            }
            return Response(transaction_data, status=status.HTTP_201_CREATED)
        except json.JSONDecodeError:
            return Response({'error': 'Invalid JSON data'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AccountDetailView(APIView, AccountAccessMixin):
    """
    Handle operations on individual accounts with proper access control.
    Only users who have access to the account can perform these operations.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, HasAccountAccess]

    def get(self, request: HttpRequest, account_id: str):
        """Get details of a specific account - only if user has access"""
        account = self.check_account_access(request.user, account_id)
        if not account:
            return Response(
                {"error": "Account not found or you don't have access to it."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        return Response({
            'id': str(account.id),
            'name': account.name,
            'balance': account.balance,
            'public_key': account.public_key
        }, status=status.HTTP_200_OK)

    def put(self, request: HttpRequest, account_id: str):
        """Update account details - only if user has access to the account"""
        try:
            data = json.loads(request.body)
            
            # Check if user has access to this account
            account = self.check_account_access(request.user, account_id)
            if not account:
                return Response(
                    {"error": "Account not found or you don't have access to it."},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Update account fields if provided
            if 'name' in data:
                account.name = data['name']
            if 'balance' in data:
                try:
                    account.balance = float(data['balance'])
                except ValueError:
                    return Response({'error': 'Invalid balance value'}, 
                                  status=status.HTTP_400_BAD_REQUEST)
            
            account.save()
            
            return Response({
                'id': str(account.id),
                'name': account.name,
                'balance': account.balance,
                'public_key': account.public_key
            }, status=status.HTTP_200_OK)

        except json.JSONDecodeError:
            return Response({'error': 'Invalid JSON data'}, 
                          status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request: HttpRequest, account_id: str):
        """Delete an account - only if user has access to the account"""
        try:
            # Check if user has access to this account
            account = self.check_account_access(request.user, account_id)
            if not account:
                return Response(
                    {"error": "Account not found or you don't have access to it."},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Check if account has any pending transactions (optional safety check)
            has_transactions = Transactions.objects.filter(
                Q(withdraw_account=account) | Q(credit_account=account)
            ).exists()
            
            force_delete = request.GET.get('force_delete', 'false').lower() == 'true'
            
            if has_transactions and not force_delete:
                return Response({
                    'error': 'Account has transaction history. Use ?force_delete=true to proceed.',
                    'transaction_count': Transactions.objects.filter(
                        Q(withdraw_account=account) | Q(credit_account=account)
                    ).count()
                }, status=status.HTTP_400_BAD_REQUEST)
            
            account_name = account.name
            account.delete()
            
            return Response({
                'message': f'Account "{account_name}" (ID: {account_id}) successfully deleted'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': str(e)}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RecurringPaymentView(APIView, AccountAccessMixin):
    """Handle CRUD operations for recurring payments"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request: HttpRequest):
        """Get all recurring payments for the current user"""
        try:
            # Get all recurring payments where user has access to withdraw account
            user_accounts = request.user.accounts.all()
            recurring_payments = RecurringPayment.objects.filter(
                withdraw_account__in=user_accounts
            ).select_related('withdraw_account', 'credit_account')

            payments_data = []
            for payment in recurring_payments:
                payments_data.append({
                    'id': str(payment.id),
                    'withdraw_account': {
                        'id': str(payment.withdraw_account.id),
                        'name': payment.withdraw_account.name
                    },
                    'credit_account': {
                        'id': str(payment.credit_account.id),
                        'name': payment.credit_account.name
                    },
                    'amount': payment.amount,
                    'message': payment.message,
                    'frequency': payment.frequency,
                    'status': payment.status,
                    'start_date': payment.start_date.isoformat(),
                    'next_payment_date': payment.next_payment_date.isoformat(),
                    'end_date': payment.end_date.isoformat() if payment.end_date else None,
                    'total_payments_made': payment.total_payments_made,
                    'max_payments': payment.max_payments,
                    'last_payment_date': payment.last_payment_date.isoformat() if payment.last_payment_date else None,
                    'created_at': payment.created_at.isoformat()
                })

            return Response({
                'recurring_payments': payments_data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': str(e)}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request: HttpRequest):
        """Create a new recurring payment"""
        try:
            data = json.loads(request.body)
            
            # Validate required fields
            required_fields = ['withdraw_account_id', 'credit_account_id', 'amount', 'message', 'frequency', 'start_date']
            for field in required_fields:
                if field not in data:
                    return Response({'error': f'Missing required field: {field}'}, 
                                  status=status.HTTP_400_BAD_REQUEST)

            # Validate amount
            try:
                amount = float(data['amount'])
                if amount <= 0:
                    return Response({'error': 'Amount must be positive'},
                                  status=status.HTTP_400_BAD_REQUEST)
            except (ValueError, TypeError):
                return Response({'error': 'Invalid amount format'},
                              status=status.HTTP_400_BAD_REQUEST)

            # Validate frequency
            valid_frequencies = ['DAILY', 'WEEKLY', 'MONTHLY', 'YEARLY']
            if data['frequency'] not in valid_frequencies:
                return Response({'error': f'Invalid frequency. Must be one of: {valid_frequencies}'},
                              status=status.HTTP_400_BAD_REQUEST)

            # Get accounts and verify access
            withdraw_account = self.check_account_access(request.user, data['withdraw_account_id'])
            if not withdraw_account:
                return Response({'error': 'You do not have access to the withdraw account'},
                              status=status.HTTP_403_FORBIDDEN)

            try:
                credit_account = Accounts.objects.get(id=data['credit_account_id'])
            except Accounts.DoesNotExist:
                return Response({'error': 'Credit account not found'},
                              status=status.HTTP_404_NOT_FOUND)

            # Parse dates
            try:
                from django.utils.dateparse import parse_datetime
                start_date = parse_datetime(data['start_date'])
                if not start_date:
                    return Response({'error': 'Invalid start_date format. Use ISO format: YYYY-MM-DDTHH:MM:SS'},
                                  status=status.HTTP_400_BAD_REQUEST)
                
                end_date = None
                if data.get('end_date'):
                    end_date = parse_datetime(data['end_date'])
                    if not end_date:
                        return Response({'error': 'Invalid end_date format. Use ISO format: YYYY-MM-DDTHH:MM:SS'},
                                      status=status.HTTP_400_BAD_REQUEST)
            except Exception:
                return Response({'error': 'Invalid date format'},
                              status=status.HTTP_400_BAD_REQUEST)

            # Validate max_payments if provided
            max_payments = data.get('max_payments')
            if max_payments is not None:
                try:
                    max_payments = int(max_payments)
                    if max_payments <= 0:
                        return Response({'error': 'max_payments must be positive'},
                                      status=status.HTTP_400_BAD_REQUEST)
                except (ValueError, TypeError):
                    return Response({'error': 'Invalid max_payments format'},
                                  status=status.HTTP_400_BAD_REQUEST)

            # Create recurring payment
            recurring_payment = RecurringPayment.objects.create(
                withdraw_account=withdraw_account,
                credit_account=credit_account,
                amount=amount,
                message=data['message'],
                frequency=data['frequency'],
                start_date=start_date,
                next_payment_date=start_date,
                end_date=end_date,
                max_payments=max_payments,
                created_by=request.user
            )

            return Response({
                'id': str(recurring_payment.id),
                'withdraw_account': {
                    'id': str(recurring_payment.withdraw_account.id),
                    'name': recurring_payment.withdraw_account.name
                },
                'credit_account': {
                    'id': str(recurring_payment.credit_account.id),
                    'name': recurring_payment.credit_account.name
                },
                'amount': recurring_payment.amount,
                'message': recurring_payment.message,
                'frequency': recurring_payment.frequency,
                'status': recurring_payment.status,
                'start_date': recurring_payment.start_date.isoformat(),
                'next_payment_date': recurring_payment.next_payment_date.isoformat(),
                'end_date': recurring_payment.end_date.isoformat() if recurring_payment.end_date else None,
                'max_payments': recurring_payment.max_payments,
                'created_at': recurring_payment.created_at.isoformat()
            }, status=status.HTTP_201_CREATED)

        except json.JSONDecodeError:
            return Response({'error': 'Invalid JSON data'}, 
                          status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RecurringPaymentDetailView(APIView, AccountAccessMixin):
    """Handle operations on individual recurring payments"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request: HttpRequest, payment_id: str):
        """Get details of a specific recurring payment"""
        try:
            recurring_payment = RecurringPayment.objects.select_related(
                'withdraw_account', 'credit_account'
            ).get(id=payment_id)

            # Check if user has access to the withdraw account
            if not self.check_account_access(request.user, str(recurring_payment.withdraw_account.id)):
                return Response(
                    {"error": "You don't have access to this recurring payment."},
                    status=status.HTTP_403_FORBIDDEN
                )

            return Response({
                'id': str(recurring_payment.id),
                'withdraw_account': {
                    'id': str(recurring_payment.withdraw_account.id),
                    'name': recurring_payment.withdraw_account.name
                },
                'credit_account': {
                    'id': str(recurring_payment.credit_account.id),
                    'name': recurring_payment.credit_account.name
                },
                'amount': recurring_payment.amount,
                'message': recurring_payment.message,
                'frequency': recurring_payment.frequency,
                'status': recurring_payment.status,
                'start_date': recurring_payment.start_date.isoformat(),
                'next_payment_date': recurring_payment.next_payment_date.isoformat(),
                'end_date': recurring_payment.end_date.isoformat() if recurring_payment.end_date else None,
                'total_payments_made': recurring_payment.total_payments_made,
                'max_payments': recurring_payment.max_payments,
                'last_payment_date': recurring_payment.last_payment_date.isoformat() if recurring_payment.last_payment_date else None,
                'created_at': recurring_payment.created_at.isoformat()
            }, status=status.HTTP_200_OK)

        except RecurringPayment.DoesNotExist:
            return Response(
                {"error": "Recurring payment not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response({'error': str(e)}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request: HttpRequest, payment_id: str):
        """Update a recurring payment"""
        try:
            data = json.loads(request.body)
            
            recurring_payment = RecurringPayment.objects.get(id=payment_id)

            # Check if user has access to the withdraw account
            if not self.check_account_access(request.user, str(recurring_payment.withdraw_account.id)):
                return Response(
                    {"error": "You don't have access to this recurring payment."},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Update allowed fields
            if 'amount' in data:
                try:
                    amount = float(data['amount'])
                    if amount <= 0:
                        return Response({'error': 'Amount must be positive'},
                                      status=status.HTTP_400_BAD_REQUEST)
                    recurring_payment.amount = amount
                except (ValueError, TypeError):
                    return Response({'error': 'Invalid amount format'},
                                  status=status.HTTP_400_BAD_REQUEST)

            if 'message' in data:
                recurring_payment.message = data['message']

            if 'status' in data:
                valid_statuses = ['ACTIVE', 'PAUSED', 'CANCELLED']
                if data['status'] not in valid_statuses:
                    return Response({'error': f'Invalid status. Must be one of: {valid_statuses}'},
                                  status=status.HTTP_400_BAD_REQUEST)
                recurring_payment.status = data['status']

            if 'end_date' in data:
                if data['end_date']:
                    from django.utils.dateparse import parse_datetime
                    end_date = parse_datetime(data['end_date'])
                    if not end_date:
                        return Response({'error': 'Invalid end_date format. Use ISO format: YYYY-MM-DDTHH:MM:SS'},
                                      status=status.HTTP_400_BAD_REQUEST)
                    recurring_payment.end_date = end_date
                else:
                    recurring_payment.end_date = None

            if 'max_payments' in data:
                if data['max_payments'] is not None:
                    try:
                        max_payments = int(data['max_payments'])
                        if max_payments <= 0:
                            return Response({'error': 'max_payments must be positive'},
                                          status=status.HTTP_400_BAD_REQUEST)
                        recurring_payment.max_payments = max_payments
                    except (ValueError, TypeError):
                        return Response({'error': 'Invalid max_payments format'},
                                      status=status.HTTP_400_BAD_REQUEST)
                else:
                    recurring_payment.max_payments = None

            recurring_payment.save()

            return Response({
                'id': str(recurring_payment.id),
                'withdraw_account': {
                    'id': str(recurring_payment.withdraw_account.id),
                    'name': recurring_payment.withdraw_account.name
                },
                'credit_account': {
                    'id': str(recurring_payment.credit_account.id),
                    'name': recurring_payment.credit_account.name
                },
                'amount': recurring_payment.amount,
                'message': recurring_payment.message,
                'frequency': recurring_payment.frequency,
                'status': recurring_payment.status,
                'start_date': recurring_payment.start_date.isoformat(),
                'next_payment_date': recurring_payment.next_payment_date.isoformat(),
                'end_date': recurring_payment.end_date.isoformat() if recurring_payment.end_date else None,
                'total_payments_made': recurring_payment.total_payments_made,
                'max_payments': recurring_payment.max_payments,
                'last_payment_date': recurring_payment.last_payment_date.isoformat() if recurring_payment.last_payment_date else None
            }, status=status.HTTP_200_OK)

        except RecurringPayment.DoesNotExist:
            return Response(
                {"error": "Recurring payment not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except json.JSONDecodeError:
            return Response({'error': 'Invalid JSON data'}, 
                          status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request: HttpRequest, payment_id: str):
        """Delete (cancel) a recurring payment"""
        try:
            recurring_payment = RecurringPayment.objects.get(id=payment_id)

            # Check if user has access to the withdraw account
            if not self.check_account_access(request.user, str(recurring_payment.withdraw_account.id)):
                return Response(
                    {"error": "You don't have access to this recurring payment."},
                    status=status.HTTP_403_FORBIDDEN
                )

            payment_info = f"Recurring payment from {recurring_payment.withdraw_account.name} to {recurring_payment.credit_account.name}"
            recurring_payment.delete()

            return Response({
                'message': f'{payment_info} successfully deleted'
            }, status=status.HTTP_200_OK)

        except RecurringPayment.DoesNotExist:
            return Response(
                {"error": "Recurring payment not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response({'error': str(e)}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)
