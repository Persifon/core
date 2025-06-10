from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db import transaction
from main.models import RecurringPayment, Transactions
import math


class Command(BaseCommand):
    help = 'Process due recurring payments'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be processed without actually executing payments',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        
        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No payments will be processed'))
        
        # Get all recurring payments that are due
        due_payments = RecurringPayment.objects.filter(
            status='ACTIVE',
            next_payment_date__lte=timezone.now()
        ).select_related('withdraw_account', 'credit_account')
        
        processed_count = 0
        failed_count = 0
        
        for recurring_payment in due_payments:
            try:
                # Check if payment should be completed
                if recurring_payment.should_be_completed():
                    if not dry_run:
                        recurring_payment.status = 'COMPLETED'
                        recurring_payment.save()
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'Marked recurring payment {recurring_payment.id} as COMPLETED'
                        )
                    )
                    continue
                
                # Check if payment is due
                if not recurring_payment.is_due_for_payment():
                    continue
                
                # Check if withdraw account has sufficient balance
                withdraw_account = recurring_payment.withdraw_account
                rounded_balance = math.ceil(withdraw_account.balance * 100) / 100
                
                if rounded_balance < recurring_payment.amount:
                    self.stdout.write(
                        self.style.ERROR(
                            f'Insufficient balance for recurring payment {recurring_payment.id}. '
                            f'Required: {recurring_payment.amount}, Available: {rounded_balance}'
                        )
                    )
                    failed_count += 1
                    continue
                
                if dry_run:
                    self.stdout.write(
                        f'Would process payment: {recurring_payment.amount} '
                        f'from {withdraw_account.name} to {recurring_payment.credit_account.name}'
                    )
                    processed_count += 1
                    continue
                
                # Process the payment using database transaction
                with transaction.atomic():
                    # Create the transaction
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
                    
                    # Update recurring payment tracking
                    recurring_payment.total_payments_made += 1
                    recurring_payment.last_payment_date = timezone.now()
                    recurring_payment.next_payment_date = recurring_payment.calculate_next_payment_date()
                    
                    # Check if this was the last payment
                    if recurring_payment.should_be_completed():
                        recurring_payment.status = 'COMPLETED'
                    
                    recurring_payment.save()
                
                self.stdout.write(
                    self.style.SUCCESS(
                        f'Processed recurring payment {recurring_payment.id}: '
                        f'{recurring_payment.amount} from {withdraw_account.name} '
                        f'to {recurring_payment.credit_account.name}. '
                        f'Transaction ID: {new_transaction.id}'
                    )
                )
                processed_count += 1
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(
                        f'Failed to process recurring payment {recurring_payment.id}: {str(e)}'
                    )
                )
                failed_count += 1
        
        # Summary
        self.stdout.write(
            self.style.SUCCESS(
                f'\nProcessing completed:'
                f'\n  Processed: {processed_count}'
                f'\n  Failed: {failed_count}'
                f'\n  Total due payments: {due_payments.count()}'
            )
        )
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING('\nThis was a dry run. No actual payments were processed.')
            )
