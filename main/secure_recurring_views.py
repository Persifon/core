# secure_recurring_views.py - Enhanced recurring payment views with security
from django.shortcuts import get_object_or_404
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework.response import Response
from rest_framework.request import HttpRequest
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
import json

from .models import Accounts, RecurringPayment
from .permissions import AccountAccessMixin
from .throttling import RecurringPaymentThrottle
from .validators import InputValidator
from .audit import AuditLogger
from .security import SecurityMonitor
from .services import RecurringPaymentService


class SecureRecurringPaymentView(APIView, AccountAccessMixin):
    """Enhanced Recurring Payment view with security features"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    throttle_classes = [RecurringPaymentThrottle]

    def __init__(self):
        super().__init__()
        self.audit_logger = AuditLogger()
        self.security_monitor = SecurityMonitor()
        self.validator = InputValidator()
        self.recurring_service = RecurringPaymentService()

    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def get(self, request: HttpRequest):
        """Get all recurring payments for the current user with audit logging"""
        try:
            client_ip = self.get_client_ip(request)
            
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

            # Log recurring payments access
            self.audit_logger.log_user_action(
                user=request.user,
                action='RECURRING_PAYMENTS_LISTED',
                resource_type='RECURRING_PAYMENT',
                resource_id='ALL',
                ip_address=client_ip,
                details={'payments_count': len(payments_data)}
            )

            return Response({
                'recurring_payments': payments_data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            self.audit_logger.log_security_event(
                user=request.user,
                action='RECURRING_PAYMENTS_LIST_ERROR',
                resource_type='RECURRING_PAYMENT',
                resource_id='ALL',
                ip_address=self.get_client_ip(request),
                severity='ERROR',
                details={'error': str(e)}
            )
            return Response({'error': 'Internal server error'}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request: HttpRequest):
        """Create a new recurring payment with enhanced validation"""
        try:
            client_ip = self.get_client_ip(request)
            
            # Monitor for suspicious activity
            if self.security_monitor.detect_suspicious_activity(request.user, client_ip):
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='RECURRING_PAYMENT_CREATE_BLOCKED',
                    resource_type='RECURRING_PAYMENT',
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
                    action='RECURRING_PAYMENT_CREATE_FAILED',
                    resource_type='RECURRING_PAYMENT',
                    resource_id='NEW',
                    ip_address=client_ip,
                    severity='INFO',
                    details={'error': 'Invalid JSON'}
                )
                return Response({'error': 'Invalid JSON data'}, 
                              status=status.HTTP_400_BAD_REQUEST)
            
            # Validate required fields
            required_fields = ['withdraw_account_id', 'credit_account_id', 'amount', 'message', 'frequency', 'start_date']
            for field in required_fields:
                if field not in data:
                    return Response({'error': f'Missing required field: {field}'}, 
                                  status=status.HTTP_400_BAD_REQUEST)

            # Validate amount
            if not self.validator.validate_amount(data['amount']):
                return Response({'error': 'Invalid amount format or value'},
                                status=status.HTTP_400_BAD_REQUEST)

            amount = float(data['amount'])

            # Validate frequency
            if not self.validator.validate_recurring_frequency(data['frequency']):
                return Response({'error': 'Invalid frequency. Must be DAILY, WEEKLY, MONTHLY, or YEARLY'},
                                status=status.HTTP_400_BAD_REQUEST)

            # Validate account IDs
            if not self.validator.validate_uuid(data['withdraw_account_id']):
                return Response({'error': 'Invalid withdraw account ID format'},
                                status=status.HTTP_400_BAD_REQUEST)
            
            if not self.validator.validate_uuid(data['credit_account_id']):
                return Response({'error': 'Invalid credit account ID format'},
                                status=status.HTTP_400_BAD_REQUEST)

            # Validate start date
            try:
                start_date = parse_datetime(data['start_date'])
                if not start_date:
                    raise ValueError()
            except (ValueError, TypeError):
                return Response({'error': 'Invalid start_date format. Use ISO format.'},
                                status=status.HTTP_400_BAD_REQUEST)

            # Validate end date if provided
            end_date = None
            if 'end_date' in data and data['end_date']:
                try:
                    end_date = parse_datetime(data['end_date'])
                    if not end_date:
                        raise ValueError()
                    if end_date <= start_date:
                        return Response({'error': 'End date must be after start date'},
                                        status=status.HTTP_400_BAD_REQUEST)
                except (ValueError, TypeError):
                    return Response({'error': 'Invalid end_date format. Use ISO format.'},
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
                    action='UNAUTHORIZED_RECURRING_PAYMENT_ATTEMPT',
                    resource_type='RECURRING_PAYMENT',
                    resource_id='NEW',
                    ip_address=client_ip,
                    severity='WARNING',
                    details={
                        'withdraw_account_id': str(withdraw_account.id),
                        'attempted_amount': amount
                    }
                )
                return Response({'error': 'You do not have permission to create recurring payments from this account'},
                                status=status.HTTP_403_FORBIDDEN)

            # Use the service to create the recurring payment
            try:
                with transaction.atomic():
                    payment = self.recurring_service.create_recurring_payment(
                        withdraw_account=withdraw_account,
                        credit_account=credit_account,
                        amount=amount,
                        message=data['message'],
                        frequency=data['frequency'],
                        start_date=start_date,
                        end_date=end_date,
                        max_payments=max_payments
                    )

                # Log successful creation
                self.audit_logger.log_financial_transaction(
                    user=request.user,
                    action='RECURRING_PAYMENT_CREATED',
                    resource_type='RECURRING_PAYMENT',
                    resource_id=str(payment.id),
                    ip_address=client_ip,
                    amount=amount,
                    details={
                        'withdraw_account_id': str(withdraw_account.id),
                        'credit_account_id': str(credit_account.id),
                        'frequency': data['frequency'],
                        'start_date': start_date.isoformat(),
                        'end_date': end_date.isoformat() if end_date else None,
                        'max_payments': max_payments
                    }
                )

                return Response({
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
                    'max_payments': payment.max_payments,
                    'created_at': payment.created_at.isoformat()
                }, status=status.HTTP_201_CREATED)

            except Exception as service_error:
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='RECURRING_PAYMENT_CREATE_FAILED',
                    resource_type='RECURRING_PAYMENT',
                    resource_id='NEW',
                    ip_address=client_ip,
                    severity='ERROR',
                    details={'error': str(service_error)}
                )
                return Response({'error': f'Failed to create recurring payment: {str(service_error)}'}, 
                              status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            self.audit_logger.log_security_event(
                user=request.user,
                action='RECURRING_PAYMENT_CREATE_ERROR',
                resource_type='RECURRING_PAYMENT',
                resource_id='NEW',
                ip_address=self.get_client_ip(request),
                severity='ERROR',
                details={'error': str(e)}
            )
            return Response({'error': 'Internal server error'}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SecureRecurringPaymentDetailView(APIView, AccountAccessMixin):
    """Enhanced individual recurring payment operations with security"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    throttle_classes = [RecurringPaymentThrottle]

    def __init__(self):
        super().__init__()
        self.audit_logger = AuditLogger()
        self.security_monitor = SecurityMonitor()
        self.validator = InputValidator()
        self.recurring_service = RecurringPaymentService()

    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def get(self, request: HttpRequest, payment_id: str):
        """Get specific recurring payment details with audit logging"""
        try:
            client_ip = self.get_client_ip(request)
            
            # Validate payment ID format
            if not self.validator.validate_uuid(payment_id):
                return Response({'error': 'Invalid payment ID format'},
                              status=status.HTTP_400_BAD_REQUEST)

            payment = get_object_or_404(RecurringPayment, id=payment_id)
            
            # Verify user owns the withdraw account
            if not request.user.accounts.filter(id=payment.withdraw_account.id).exists():
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='UNAUTHORIZED_RECURRING_PAYMENT_ACCESS',
                    resource_type='RECURRING_PAYMENT',
                    resource_id=payment_id,
                    ip_address=client_ip,
                    severity='WARNING',
                    details={'payment_id': payment_id}
                )
                return Response(
                    {"detail": "You don't have access to this recurring payment."},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Log payment access
            self.audit_logger.log_user_action(
                user=request.user,
                action='RECURRING_PAYMENT_VIEWED',
                resource_type='RECURRING_PAYMENT',
                resource_id=payment_id,
                ip_address=client_ip,
                details={'amount': payment.amount, 'status': payment.status}
            )

            payment_data = {
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
            }

            return Response(payment_data, status=status.HTTP_200_OK)

        except RecurringPayment.DoesNotExist:
            return Response(
                {"detail": "Recurring payment not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            self.audit_logger.log_security_event(
                user=request.user,
                action='RECURRING_PAYMENT_ACCESS_ERROR',
                resource_type='RECURRING_PAYMENT',
                resource_id=payment_id,
                ip_address=self.get_client_ip(request),
                severity='ERROR',
                details={'error': str(e)}
            )
            return Response({'error': 'Internal server error'}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def patch(self, request: HttpRequest, payment_id: str):
        """Update recurring payment status (pause/resume/cancel) with audit logging"""
        try:
            client_ip = self.get_client_ip(request)
            
            # Validate payment ID format
            if not self.validator.validate_uuid(payment_id):
                return Response({'error': 'Invalid payment ID format'},
                              status=status.HTTP_400_BAD_REQUEST)

            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                return Response({'error': 'Invalid JSON data'}, 
                              status=status.HTTP_400_BAD_REQUEST)

            payment = get_object_or_404(RecurringPayment, id=payment_id)
            
            # Verify user owns the withdraw account
            if not request.user.accounts.filter(id=payment.withdraw_account.id).exists():
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='UNAUTHORIZED_RECURRING_PAYMENT_UPDATE',
                    resource_type='RECURRING_PAYMENT',
                    resource_id=payment_id,
                    ip_address=client_ip,
                    severity='WARNING',
                    details={'payment_id': payment_id}
                )
                return Response(
                    {"detail": "You don't have access to this recurring payment."},
                    status=status.HTTP_403_FORBIDDEN
                )

            old_status = payment.status
            updated = False

            # Handle status updates
            if 'status' in data:
                new_status = data['status'].upper()
                if new_status in ['ACTIVE', 'PAUSED', 'CANCELLED']:
                    if new_status != payment.status:
                        try:
                            if new_status == 'ACTIVE':
                                self.recurring_service.resume_payment(payment)
                            elif new_status == 'PAUSED':
                                self.recurring_service.pause_payment(payment)
                            elif new_status == 'CANCELLED':
                                self.recurring_service.cancel_payment(payment)
                            updated = True
                        except Exception as service_error:
                            return Response({'error': str(service_error)}, 
                                          status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({'error': 'Invalid status. Must be ACTIVE, PAUSED, or CANCELLED'}, 
                                  status=status.HTTP_400_BAD_REQUEST)

            if updated:
                # Log status change
                self.audit_logger.log_financial_transaction(
                    user=request.user,
                    action='RECURRING_PAYMENT_STATUS_CHANGED',
                    resource_type='RECURRING_PAYMENT',
                    resource_id=payment_id,
                    ip_address=client_ip,
                    amount=payment.amount,
                    details={
                        'old_status': old_status,
                        'new_status': payment.status,
                        'payment_id': payment_id
                    }
                )

                return Response({
                    'id': str(payment.id),
                    'status': payment.status,
                    'message': f'Recurring payment status updated from {old_status} to {payment.status}'
                }, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'No changes made'}, status=status.HTTP_200_OK)

        except RecurringPayment.DoesNotExist:
            return Response(
                {"detail": "Recurring payment not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            self.audit_logger.log_security_event(
                user=request.user,
                action='RECURRING_PAYMENT_UPDATE_ERROR',
                resource_type='RECURRING_PAYMENT',
                resource_id=payment_id,
                ip_address=self.get_client_ip(request),
                severity='ERROR',
                details={'error': str(e)}
            )
            return Response({'error': 'Internal server error'}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request: HttpRequest, payment_id: str):
        """Delete recurring payment with audit logging"""
        try:
            client_ip = self.get_client_ip(request)
            
            # Validate payment ID format
            if not self.validator.validate_uuid(payment_id):
                return Response({'error': 'Invalid payment ID format'},
                              status=status.HTTP_400_BAD_REQUEST)

            payment = get_object_or_404(RecurringPayment, id=payment_id)
            
            # Verify user owns the withdraw account
            if not request.user.accounts.filter(id=payment.withdraw_account.id).exists():
                self.audit_logger.log_security_event(
                    user=request.user,
                    action='UNAUTHORIZED_RECURRING_PAYMENT_DELETE',
                    resource_type='RECURRING_PAYMENT',
                    resource_id=payment_id,
                    ip_address=client_ip,
                    severity='WARNING',
                    details={'payment_id': payment_id}
                )
                return Response(
                    {"detail": "You don't have access to this recurring payment."},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Store details for audit log before deletion
            payment_details = {
                'amount': payment.amount,
                'frequency': payment.frequency,
                'status': payment.status,
                'total_payments_made': payment.total_payments_made,
                'withdraw_account_id': str(payment.withdraw_account.id),
                'credit_account_id': str(payment.credit_account.id)
            }

            # Delete the payment
            with transaction.atomic():
                payment.delete()

            # Log deletion
            self.audit_logger.log_financial_transaction(
                user=request.user,
                action='RECURRING_PAYMENT_DELETED',
                resource_type='RECURRING_PAYMENT',
                resource_id=payment_id,
                ip_address=client_ip,
                amount=payment_details['amount'],
                details=payment_details
            )

            return Response({
                'message': f'Recurring payment {payment_id} successfully deleted'
            }, status=status.HTTP_200_OK)

        except RecurringPayment.DoesNotExist:
            return Response(
                {"detail": "Recurring payment not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            self.audit_logger.log_security_event(
                user=request.user,
                action='RECURRING_PAYMENT_DELETE_ERROR',
                resource_type='RECURRING_PAYMENT',
                resource_id=payment_id,
                ip_address=self.get_client_ip(request),
                severity='ERROR',
                details={'error': str(e)}
            )
            return Response({'error': 'Internal server error'}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)
