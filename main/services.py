from decimal import Decimal
from django.db import transaction
from django.utils import timezone
from .models import RecurringPayment, Transactions, Accounts, POSTerminal, POSTransactionData
import math
import logging

logger = logging.getLogger(__name__)


class POSService:
    @staticmethod
    @transaction.atomic
    def acquire_transaction(validated_data: dict, merchant_account: Accounts, pos_terminal: POSTerminal) -> Transactions:
        """
        Processes a POS acquiring transaction.

        Args:
            validated_data (dict): Validated data from POSAcquiringTransactionRequestSerializer.
            merchant_account (Accounts): The merchant\'s account to credit.
            pos_terminal (POSTerminal): The POS terminal initiating the transaction.

        Returns:
            Transactions: The created transaction object.
        
        Raises:
            Exception: If any part of the transaction processing fails.
        """
        amount = validated_data['amount']
        # Ensure currency is handled correctly, defaulting to merchant account\'s currency
        currency = validated_data.get('currency', merchant_account.currency)

        # 1. Create the Transaction
        new_transaction = Transactions.objects.create(
            transaction_type='POS_SALE',
            amount=Decimal(str(amount)), # Ensure amount is Decimal
            currency=currency,
            from_account=None,  # No \'from_account\' for POS acquiring
            to_account=merchant_account,
            description=f"POS Sale via terminal {pos_terminal.name} ({pos_terminal.terminal_id_code})",
            status='COMPLETED', # POS transactions are typically completed immediately
            transaction_date=timezone.now()
        )

        # 2. Create POS Transaction Specific Data
        POSTransactionData.objects.create(
            transaction=new_transaction,
            terminal=pos_terminal,
            emv_tags=validated_data.get('emv_tags'),
            card_brand=validated_data.get('card_brand'),
            pan_last_four=validated_data.get('pan_last_four'),
            authorization_code=validated_data.get('authorization_code'),
            entry_mode=validated_data.get('entry_mode')
        )

        # 3. Update Merchant Account Balance
        # Ensure merchant_account.balance is Decimal before addition
        if not isinstance(merchant_account.balance, Decimal):
            merchant_account.balance = Decimal(str(merchant_account.balance))
        
        merchant_account.balance += Decimal(str(amount))
        merchant_account.save(update_fields=['balance'])

        logger.info(f"POS transaction {new_transaction.id} acquired for terminal {pos_terminal.terminal_id_code} to account {merchant_account.public_key}")
        return new_transaction


class RecurringPaymentService:
    """Service class to handle recurring payment operations"""
    
    @staticmethod
    def create_recurring_payment(withdraw_account, credit_account, amount, message, 
                               frequency, start_date, created_by, end_date=None, max_payments=None):
        """Create a new recurring payment with validation"""
        try:
            with transaction.atomic():
                recurring_payment = RecurringPayment.objects.create(
                    withdraw_account=withdraw_account,
                    credit_account=credit_account,
                    amount=amount,
                    message=message,
                    frequency=frequency,
                    start_date=start_date,
                    next_payment_date=start_date,
                    end_date=end_date,
                    max_payments=max_payments,
                    created_by=created_by
                )
                
                logger.info(f"Created recurring payment {recurring_payment.id}")
                return recurring_payment
                
        except Exception as e:
            logger.error(f"Failed to create recurring payment: {str(e)}")
            raise
    
    @staticmethod
    def process_single_payment(recurring_payment):
        """Process a single recurring payment"""
        try:
            with transaction.atomic():
                # Validate payment can be processed
                if not recurring_payment.is_due_for_payment():
                    return False, "Payment is not due yet"
                
                if recurring_payment.should_be_completed():
                    recurring_payment.status = 'COMPLETED'
                    recurring_payment.save()
                    return False, "Payment has been completed"
                
                # Check balance
                withdraw_account = recurring_payment.withdraw_account
                rounded_balance = math.ceil(withdraw_account.balance * 100) / 100
                
                if rounded_balance < recurring_payment.amount:
                    return False, f"Insufficient balance. Required: {recurring_payment.amount}, Available: {rounded_balance}"
                
                # Create transaction
                new_transaction = Transactions.objects.create(
                    withdraw_account=withdraw_account,
                    credit_account=recurring_payment.credit_account,
                    amount=recurring_payment.amount,
                    message=f"Recurring payment: {recurring_payment.message}"
                )
                
                # Update account balances
                withdraw_account.balance = math.ceil(
                    (withdraw_account.balance - recurring_payment.amount) * 100
                ) / 100
                
                recurring_payment.credit_account.balance = math.ceil(
                    (recurring_payment.credit_account.balance + recurring_payment.amount) * 100
                ) / 100
                
                withdraw_account.save()
                recurring_payment.credit_account.save()
                
                # Update recurring payment
                recurring_payment.total_payments_made += 1
                recurring_payment.last_payment_date = timezone.now()
                recurring_payment.next_payment_date = recurring_payment.calculate_next_payment_date()
                
                # Check if this was the last payment
                if recurring_payment.should_be_completed():
                    recurring_payment.status = 'COMPLETED'
                
                recurring_payment.save()
                
                logger.info(f"Processed recurring payment {recurring_payment.id}, transaction {new_transaction.id}")
                return True, f"Payment processed successfully. Transaction ID: {new_transaction.id}"
                
        except Exception as e:
            logger.error(f"Failed to process recurring payment {recurring_payment.id}: {str(e)}")
            return False, f"Processing failed: {str(e)}"
    
    @staticmethod
    def pause_recurring_payment(recurring_payment):
        """Pause a recurring payment"""
        if recurring_payment.status == 'ACTIVE':
            recurring_payment.status = 'PAUSED'
            recurring_payment.save()
            return True, "Recurring payment paused"
        return False, "Can only pause active payments"
    
    @staticmethod
    def resume_recurring_payment(recurring_payment):
        """Resume a paused recurring payment"""
        if recurring_payment.status == 'PAUSED':
            recurring_payment.status = 'ACTIVE'
            recurring_payment.save()
            return True, "Recurring payment resumed"
        return False, "Can only resume paused payments"
    
    @staticmethod
    def cancel_recurring_payment(recurring_payment):
        """Cancel a recurring payment"""
        if recurring_payment.status in ['ACTIVE', 'PAUSED']:
            recurring_payment.status = 'CANCELLED'
            recurring_payment.save()
            return True, "Recurring payment cancelled"
        return False, "Payment is already completed or cancelled"
    
    @staticmethod
    def get_due_payments():
        """Get all recurring payments that are due for processing"""
        return RecurringPayment.objects.filter(
            status='ACTIVE',
            next_payment_date__lte=timezone.now()
        ).select_related('withdraw_account', 'credit_account')
    
    @staticmethod
    def get_user_recurring_payments(user):
        """Get all recurring payments for a user"""
        user_accounts = user.accounts.all()
        return RecurringPayment.objects.filter(
            withdraw_account__in=user_accounts
        ).select_related('withdraw_account', 'credit_account').order_by('-created_at')
