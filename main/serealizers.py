from rest_framework import serializers
from django.utils import timezone
from decimal import Decimal, InvalidOperation

from .models import Accounts, Transactions, RecurringPayment, Profile, POSTerminal, POSTransactionData


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ('id', 'username', 'first_name', 'family_name', 'last_name', 'email', 'two_factor_enabled') 
        read_only_fields = ('id', 'email', 'username', 'two_factor_enabled', 'first_name', 'family_name', 'last_name')

class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Accounts
        fields = ('id', 'name', 'balance', 'public_key')
        read_only_fields = ('id', 'balance', 'public_key')

    def validate_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("Account name cannot be empty.")
        return value

class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transactions
        # Explicitly list fields instead of '__all__' for clarity when extending
        fields = [
            'id', 'from_account', 'to_account', 'amount', 'currency', 
            'transaction_type', 'status', 'created_at', 'updated_at', 
            'description', 'created_by'
        ]
        read_only_fields = ('id', 'created_at', 'updated_at', 'status')

    def validate_amount(self, value):
        try:
            value = Decimal(str(value))
        except InvalidOperation as e:
            raise serializers.ValidationError("Amount must be a valid decimal number.") from e
        if value <= Decimal('0.00'):
            raise serializers.ValidationError("Transaction amount must be positive.")
        if value.quantize(Decimal('0.01')) != value:
            raise serializers.ValidationError("Amount can have at most two decimal places.")
        return value

    def validate(self, attrs):
        from_account = attrs.get('from_account')
        to_account = attrs.get('to_account')
        transaction_type = attrs.get('transaction_type')

        if transaction_type != 'POS_SALE' and not from_account:
            raise serializers.ValidationError({"from_account": "Source account is required for this transaction type."}) 

        if from_account and from_account == to_account:
            raise serializers.ValidationError("Sender and receiver accounts cannot be the same.")
        return attrs

class RecurringPaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = RecurringPayment
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at', 'created_by', 'last_payment_date', 'total_payments_made')

    def validate_amount(self, value):
        try:
            value = Decimal(str(value))
        except InvalidOperation as e:
            raise serializers.ValidationError("Amount must be a valid decimal number.") from e
        if value <= Decimal('0.00'):
            raise serializers.ValidationError("Payment amount must be positive.")
        if value.quantize(Decimal('0.01')) != value:
            raise serializers.ValidationError("Amount can have at most two decimal places.")
        return value

    def validate(self, attrs):
        if attrs.get('withdraw_account') == attrs.get('credit_account'):
            raise serializers.ValidationError("Withdraw and credit accounts cannot be the same.")
        
        start_date = attrs.get('start_date')
        end_date = attrs.get('end_date')

        if start_date and start_date < timezone.now():
            if not (self.instance and self.instance.start_date == start_date):
                raise serializers.ValidationError("Start date cannot be in the past.")

        if end_date and start_date and end_date < start_date:
            raise serializers.ValidationError("End date cannot be before the start date.")

        if 'next_payment_date' not in attrs or not attrs.get('next_payment_date'):
            if start_date:
                attrs['next_payment_date'] = start_date
        return attrs

# --- POS Serializers ---

class POSTerminalSerializer(serializers.ModelSerializer):
    class Meta:
        model = POSTerminal
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')

    def validate_merchant_account(self, value):
        if not value:
            raise serializers.ValidationError("Merchant account must be valid.")
        # Add active check if Accounts model gets an 'is_active' field
        # if hasattr(value, 'is_active') and not value.is_active:
        #     raise serializers.ValidationError("Merchant account is not active.")
        return value

class POSTransactionDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = POSTransactionData
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'transaction')

    def validate_emv_tags(self, value):
        if value:
            if not isinstance(value, dict):
                raise serializers.ValidationError("EMV tags must be a valid JSON object.")
        return value

    def validate_pan_last_four(self, value):
        if value and (not value.isdigit() or len(value) != 4):
            raise serializers.ValidationError("PAN last four must be exactly 4 digits.")
        return value

class POSAcquiringTransactionRequestSerializer(serializers.Serializer):
    terminal_id_code = serializers.CharField(max_length=100)
    amount = serializers.DecimalField(max_digits=10, decimal_places=2)
    currency = serializers.CharField(max_length=3, default='USD')
    emv_tags = serializers.JSONField(required=False, allow_null=True)
    pan_last_four = serializers.CharField(max_length=4, required=False, allow_null=True)
    card_brand = serializers.CharField(max_length=50, required=False, allow_null=True)
    entry_mode = serializers.CharField(max_length=20, required=False, allow_null=True)
    authorization_code = serializers.CharField(max_length=50, required=False, allow_null=True)

    def validate_amount(self, value):
        if value <= Decimal('0.00'):
            raise serializers.ValidationError("Transaction amount must be positive.")
        return value

    def validate_terminal_id_code(self, value):
        try:
            # Linter might complain, but this is standard Django ORM access
            terminal = POSTerminal.objects.get(terminal_id_code=value, is_active=True)
            self.context['terminal_instance'] = terminal 
        except POSTerminal.DoesNotExist as e: 
            # Linter might complain, but this is standard Django ORM access
            raise serializers.ValidationError("Active terminal with this ID code not found.") from e
        return value

    def validate_emv_tags(self, value):
        if value:
            if not isinstance(value, dict):
                raise serializers.ValidationError("EMV tags must be a valid JSON object (dictionary).")
            forbidden_tags = ['Track1Data', 'Track2Data', 'PAN', 'CVV', 'PINBlock'] 
            for tag in forbidden_tags:
                if tag in value:
                    raise serializers.ValidationError(f"Sensitive EMV tag '{tag}' should not be present.")
        return value
    
    # Adding placeholder create/update to satisfy linters if they expect them for all Serializer subclasses
    def create(self, validated_data):
        raise NotImplementedError("This serializer is for request validation only and does not create objects.")

    def update(self, instance, validated_data):
        raise NotImplementedError("This serializer is for request validation only and does not update objects.")

class TransactionDetailSerializer(TransactionSerializer):
    pos_data = POSTransactionDataSerializer(read_only=True, allow_null=True)
    from_account_details = AccountSerializer(source='from_account', read_only=True, allow_null=True)
    to_account_details = AccountSerializer(source='to_account', read_only=True)
    created_by_details = ProfileSerializer(source='created_by', read_only=True, allow_null=True)

    class Meta(TransactionSerializer.Meta):
        # Explicitly inherit and extend fields from the base TransactionSerializer
        fields = list(TransactionSerializer.Meta.fields) + ['pos_data', 'from_account_details', 'to_account_details', 'created_by_details']