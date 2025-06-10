from rest_framework import serializers
from .models import (
    Profile, Accounts, Transactions, RecurringPayment, 
    POSTerminal, POSTransactionData, APIKey
)
from django.contrib.auth import get_user_model
from django.utils import timezone
from decimal import Decimal, InvalidOperation
import math

User = get_user_model()

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'date_joined', 'last_login')
        read_only_fields = ('date_joined', 'last_login')

class AccountSerializer(serializers.ModelSerializer):
    user = serializers.ReadOnlyField(source='user.username')
    balance = serializers.DecimalField(max_digits=12, decimal_places=2, coerce_to_string=False)

    class Meta:
        model = Accounts
        fields = ('id', 'user', 'account_name', 'balance', 'public_key', 'created_at', 'updated_at')
        read_only_fields = ('id', 'user', 'created_at', 'updated_at')

    def validate_balance(self, value):
        if value < 0:
            raise serializers.ValidationError("Balance cannot be negative.")
        return math.ceil(value * 100) / 100

class TransactionSerializer(serializers.ModelSerializer):
    from_account_id = serializers.UUIDField(write_only=True, required=False, allow_null=True)
    to_account_id = serializers.UUIDField(write_only=True)
    
    from_account_details = AccountSerializer(source='from_account', read_only=True)
    to_account_details = AccountSerializer(source='to_account', read_only=True)

    amount = serializers.DecimalField(max_digits=10, decimal_places=2, min_value=Decimal('0.01'))

    class Meta:
        model = Transactions
        fields = (
            'id', 'from_account_id', 'to_account_id', 'from_account_details', 'to_account_details', 
            'amount', 'transaction_type', 'description', 'status', 'created_at', 'updated_at'
        )
        read_only_fields = ('id', 'status', 'created_at', 'updated_at', 'from_account_details', 'to_account_details')
        extra_kwargs = {
            'transaction_type': {'default': 'TRANSFER'},
            'description': {'required': False, 'allow_blank': True}
        }

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Transaction amount must be positive.")
        return math.ceil(value * 100) / 100

    def validate(self, data):
        from_account_id = data.get('from_account_id')
        to_account_id = data.get('to_account_id')

        if from_account_id and from_account_id == to_account_id:
            raise serializers.ValidationError("Sender and receiver accounts cannot be the same.")
        
        # Further validation can be added here, e.g., checking account existence
        # This is often better handled in the view or service layer to provide current user context
        return data

class TransactionDetailSerializer(TransactionSerializer):
    # Inherits from TransactionSerializer, can add more fields or override as needed
    # For now, it's the same for detail view
    pass


class RecurringPaymentSerializer(serializers.ModelSerializer):
    from_account_id = serializers.UUIDField(write_only=True)
    to_account_id = serializers.UUIDField(write_only=True)
    
    from_account_details = AccountSerializer(source='from_account', read_only=True)
    to_account_details = AccountSerializer(source='to_account', read_only=True)

    amount = serializers.DecimalField(max_digits=10, decimal_places=2, min_value=Decimal('0.01'))
    next_payment_date = serializers.DateField(read_only=True) # Handled by service

    class Meta:
        model = RecurringPayment
        fields = (
            'id', 'from_account_id', 'to_account_id', 'from_account_details', 'to_account_details',
            'amount', 'frequency', 'start_date', 'end_date', 'status', 
            'next_payment_date', 'payments_made', 'max_payments', 'created_at', 'updated_at'
        )
        read_only_fields = ('id', 'next_payment_date', 'payments_made', 'created_at', 'updated_at')

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Recurring payment amount must be positive.")
        return math.ceil(value * 100) / 100

    def validate_start_date(self, value):
        if value < timezone.now().date():
            raise serializers.ValidationError("Start date cannot be in the past.")
        return value

    def validate(self, data):
        from_account_id = data.get('from_account_id')
        to_account_id = data.get('to_account_id')
        start_date = data.get('start_date')
        end_date = data.get('end_date')

        if from_account_id == to_account_id:
            raise serializers.ValidationError("Sender and receiver accounts cannot be the same for recurring payments.")

        if end_date and start_date and end_date < start_date:
            raise serializers.ValidationError("End date cannot be before the start date.")
        
        # Ensure accounts exist (can also be done in view/service)
        try:
            Accounts.objects.get(pk=from_account_id)
        except Accounts.DoesNotExist:
            raise serializers.ValidationError({"from_account_id": "From account does not exist."})
        
        try:
            Accounts.objects.get(pk=to_account_id)
        except Accounts.DoesNotExist:
            raise serializers.ValidationError({"to_account_id": "To account does not exist."})
            
        return data

class POSTerminalSerializer(serializers.ModelSerializer):
    merchant_account_id = serializers.UUIDField(source='merchant_account.id', write_only=True)
    merchant_account_details = AccountSerializer(source='merchant_account', read_only=True)
    api_key_id = serializers.UUIDField(source='api_key.id', write_only=True, required=False, allow_null=True)
    # api_key_details can be added if needed, but might expose sensitive info if not handled carefully

    class Meta:
        model = POSTerminal
        fields = (
            'id', 'terminal_id_code', 'merchant_account_id', 'merchant_account_details', 
            'api_key_id', 'name', 'location', 'is_active', 'created_at', 'updated_at'
        )
        read_only_fields = ('id', 'created_at', 'updated_at', 'merchant_account_details')
        extra_kwargs = {
            'terminal_id_code': {'validators': []}, # Allow for potential updates if needed, or keep unique validation
        }

    def validate_merchant_account_id(self, value):
        try:
            account = Accounts.objects.get(pk=value)
            # Optionally, check if the user creating this terminal owns this account,
            # but that's better handled in the view based on request.user
            return value
        except Accounts.DoesNotExist:
            raise serializers.ValidationError("Merchant account does not exist.")

    def validate_api_key_id(self, value):
        if value: # if an API key ID is provided
            try:
                APIKey.objects.get(pk=value, is_active=True) # Ensure API key exists and is active
            except APIKey.DoesNotExist:
                raise serializers.ValidationError("Active API key with this ID does not exist.")
        return value

class POSTransactionDataSerializer(serializers.ModelSerializer):
    transaction_id = serializers.UUIDField(source='transaction.id', read_only=True) # Read-only, set by system

    class Meta:
        model = POSTransactionData
        fields = (
            'id', 'transaction_id', 'emv_tags', 'card_brand', 
            'pan_last_four', 'authorization_code', 'entry_mode', 'created_at'
        )
        read_only_fields = ('id', 'transaction_id', 'created_at')


class POSAcquiringTransactionRequestSerializer(serializers.Serializer):
    terminal_id_code = serializers.CharField(max_length=50)
    amount = serializers.DecimalField(max_digits=10, decimal_places=2, min_value=Decimal('0.01'))
    currency = serializers.CharField(max_length=3, default='USD') # Assuming USD for now
    
    # Optional POS Data fields
    emv_tags = serializers.CharField(required=False, allow_blank=True)
    card_brand = serializers.CharField(max_length=50, required=False, allow_blank=True)
    pan_last_four = serializers.CharField(max_length=4, required=False, allow_blank=True)
    entry_mode = serializers.ChoiceField(
        choices=POSTransactionData.ENTRY_MODES, 
        required=False, 
        allow_blank=True
    )
    # No authorization_code here, that's part of the response from an acquirer/processor

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Transaction amount must be positive.")
        try:
            # Ensure it's a valid decimal and round it
            valid_decimal = Decimal(value)
            if valid_decimal.as_tuple().exponent < -2: # More than 2 decimal places
                raise serializers.ValidationError("Amount cannot have more than two decimal places.")
            return math.ceil(valid_decimal * 100) / 100
        except InvalidOperation:
            raise serializers.ValidationError("Invalid amount format.")

    def validate_currency(self, value):
        # For now, only USD is supported. This can be expanded later.
        if value.upper() != 'USD':
            raise serializers.ValidationError("Currently, only USD currency is supported.")
        return value.upper()

    def validate_pan_last_four(self, value):
        if value and (not value.isdigit() or len(value) != 4):
            raise serializers.ValidationError("PAN last four must be 4 digits.")
        return value
