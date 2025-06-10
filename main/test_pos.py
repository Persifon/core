from django.test import TestCase
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from main.models import POSTerminal, POSTransactionData, Accounts, APIKey, Transactions
from decimal import Decimal
import uuid
from .serializers import POSAcquiringTransactionRequestSerializer, POSTerminalSerializer, POSTransactionDataSerializer
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIRequestFactory, APITestCase
from rest_framework import status
from unittest.mock import patch, MagicMock
from main.api_key_middleware import APIKeyUser # Added import

from main.views_pos import POSAcquiringView
from main.serealizers import TransactionDetailSerializer # Corrected typo

User = get_user_model()

class POSTerminalModelTests(TestCase):
    def setUp(self):
        self.merchant_user = User.objects.create_user(
            username='merchant_test_user_models',
            password='testpassword123',
            email='merchant_models@example.com',
            first_name='Merchant',
            last_name='UserModels'
        )
        self.merchant_account = Accounts.objects.create(
            user=self.merchant_user,
            account_name='Merchant Main Account Models',
            balance=Decimal('1000.00')
        )
        # Assuming APIKey.objects.create_key is a method that returns (instance, key_string)
        self.api_key_instance, _ = APIKey.objects.create_key(
            name='Test POS API Key For Models',
            user=self.merchant_user,
            permissions=['pos_terminal_access'] # Example permission
        )

    def test_create_pos_terminal(self):
        terminal = POSTerminal.objects.create(
            terminal_id_code='TERM001M',
            merchant_account=self.merchant_account,
            api_key=self.api_key_instance,
            name='Main Counter Terminal Models',
            location='Store Front Models'
            # is_active defaults to True
        )
        self.assertIsNotNone(terminal.id)
        self.assertEqual(terminal.terminal_id_code, 'TERM001M')
        self.assertEqual(terminal.merchant_account, self.merchant_account)
        self.assertEqual(terminal.api_key, self.api_key_instance)
        self.assertEqual(terminal.name, 'Main Counter Terminal Models')
        self.assertEqual(terminal.location, 'Store Front Models')
        self.assertTrue(terminal.is_active)
        self.assertEqual(str(terminal), "Main Counter Terminal Models (TERM001M)")

    def test_pos_terminal_str_method(self):
        terminal = POSTerminal.objects.create(
            terminal_id_code='TERM002M',
            merchant_account=self.merchant_account,
            name='Secondary Terminal Models'
            # api_key can be null
        )
        self.assertEqual(str(terminal), "Secondary Terminal Models (TERM002M)")

    def test_pos_terminal_default_is_active(self):
        terminal = POSTerminal.objects.create(
            terminal_id_code='TERM003M',
            merchant_account=self.merchant_account,
            name='Test Active Default Models'
        )
        self.assertTrue(terminal.is_active)

    def test_pos_terminal_can_be_inactive(self):
        terminal = POSTerminal.objects.create(
            terminal_id_code='TERM004M',
            merchant_account=self.merchant_account,
            name='Inactive Terminal Models',
            is_active=False
        )
        self.assertFalse(terminal.is_active)

class POSTransactionDataModelTests(TestCase):
    def setUp(self):
        self.merchant_user = User.objects.create_user(
            username='merchant_data_user_models',
            password='datapassword123',
            email='merchant_data_models@example.com'
        )
        self.merchant_account = Accounts.objects.create(
            user=self.merchant_user,
            account_name='Merchant Account for POS Data Models',
            balance=Decimal('500.00')
        )
        self.pos_transaction_instance = Transactions.objects.create(
            to_account=self.merchant_account,
            amount=Decimal('123.45'),
            transaction_type='POS_SALE',
            description='Test POS Sale for Data Model Models'
            # from_account is null for POS_SALE
        )

    def test_create_pos_transaction_data(self):
        pos_data = POSTransactionData.objects.create(
            transaction=self.pos_transaction_instance,
            emv_tags='9F02060000000012349F0306000000000000',
            card_brand='VISA',
            pan_last_four='1234',
            authorization_code='AUTH123M',
            entry_mode='CHIP_INSERT' # Assuming CHIP_INSERT is a valid choice
        )
        self.assertIsNotNone(pos_data.id) # Assuming it has its own ID
        self.assertEqual(pos_data.transaction, self.pos_transaction_instance)
        self.assertEqual(pos_data.emv_tags, '9F02060000000012349F0306000000000000')
        self.assertEqual(pos_data.card_brand, 'VISA')
        self.assertEqual(pos_data.pan_last_four, '1234')
        self.assertEqual(pos_data.authorization_code, 'AUTH123M')
        self.assertEqual(pos_data.entry_mode, 'CHIP_INSERT')
        self.assertEqual(str(pos_data), f"POS Data for Transaction {self.pos_transaction_instance.id} - Amount: 123.45")

    def test_pos_transaction_data_str_method(self):
        another_pos_tx = Transactions.objects.create(
            to_account=self.merchant_account,
            amount=Decimal('50.00'),
            transaction_type='POS_SALE',
            description='Another POS Sale Models'
        )
        pos_data = POSTransactionData.objects.create(
            transaction=another_pos_tx,
            pan_last_four='5678',
            card_brand='MASTERCARD'
        )
        expected_str = f"POS Data for Transaction {another_pos_tx.id} - Amount: 50.00"
        self.assertEqual(str(pos_data), expected_str)

    def test_pos_transaction_data_requires_transaction_field(self):
        # Assuming 'transaction' field is non-nullable and not the primary key itself.
        # If POSTransactionData.transaction is OneToOneField(primary_key=True), this test is different.
        # Assuming it's OneToOneField(null=False)
        field = POSTransactionData._meta.get_field('transaction')
        if not field.primary_key: # If it's not the PK, it can raise IntegrityError if null=False
            self.assertFalse(field.null, "Transaction field on POSTransactionData should be non-nullable if not PK.")
            with self.assertRaises(IntegrityError):
                POSTransactionData.objects.create(
                    pan_last_four='0000',
                    card_brand='TEST_BRAND'
                    # Missing transaction
                )
        else: # If it is the PK, it cannot be null by definition.
             with self.assertRaises(TypeError): # Or similar error for missing PK
                POSTransactionData.objects.create(
                    pan_last_four='0000',
                    card_brand='TEST_BRAND'
                )

class POSAcquiringTransactionRequestSerializerTests(TestCase):
    def test_valid_data(self):
        data = {
            "terminal_id_code": "TERM001",
            "amount": "100.50",
            "currency": "USD",
            "emv_tags": "test_emv_tags",
            "card_brand": "VISA",
            "pan_last_four": "1234",
            "entry_mode": "CHIP_INSERT"
        }
        serializer = POSAcquiringTransactionRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        validated_data = serializer.validated_data
        self.assertEqual(validated_data['terminal_id_code'], "TERM001")
        self.assertEqual(validated_data['amount'], Decimal('100.50'))
        self.assertEqual(validated_data['currency'], "USD")
        self.assertEqual(validated_data['emv_tags'], "test_emv_tags")
        self.assertEqual(validated_data['card_brand'], "VISA")
        self.assertEqual(validated_data['pan_last_four'], "1234")
        self.assertEqual(validated_data['entry_mode'], "CHIP_INSERT")

    def test_missing_required_fields(self):
        data = {
            "currency": "USD"
            # terminal_id_code and amount are missing
        }
        serializer = POSAcquiringTransactionRequestSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('terminal_id_code', serializer.errors)
        self.assertIn('amount', serializer.errors)

    def test_invalid_amount_zero(self):
        data = {"terminal_id_code": "T1", "amount": "0.00", "currency": "USD"}
        serializer = POSAcquiringTransactionRequestSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('amount', serializer.errors)
        self.assertEqual(str(serializer.errors['amount'][0]), "Transaction amount must be positive.")

    def test_invalid_amount_negative(self):
        data = {"terminal_id_code": "T1", "amount": "-10.00", "currency": "USD"}
        serializer = POSAcquiringTransactionRequestSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('amount', serializer.errors)
        self.assertEqual(str(serializer.errors['amount'][0]), "Transaction amount must be positive.")

    def test_invalid_amount_format(self):
        data = {"terminal_id_code": "T1", "amount": "abc", "currency": "USD"}
        serializer = POSAcquiringTransactionRequestSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('amount', serializer.errors)
        # The exact error message might vary slightly based on DRF/Decimal conversion
        self.assertTrue("valid number" in str(serializer.errors['amount'][0]).lower() or \
                        "invalid amount format" in str(serializer.errors['amount'][0]).lower())


    def test_amount_rounding_and_decimal_places(self):
        # Test rounding up
        data = {"terminal_id_code": "T1", "amount": "10.125", "currency": "USD"}
        serializer = POSAcquiringTransactionRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data['amount'], Decimal('10.13'))

        # Test more than 2 decimal places - should fail validation
        data_invalid_decimals = {"terminal_id_code": "T1", "amount": "10.1234", "currency": "USD"}
        serializer_invalid_decimals = POSAcquiringTransactionRequestSerializer(data=data_invalid_decimals)
        self.assertFalse(serializer_invalid_decimals.is_valid())
        self.assertIn('amount', serializer_invalid_decimals.errors)
        self.assertEqual(str(serializer_invalid_decimals.errors['amount'][0]), "Amount cannot have more than two decimal places.")

        # Test exactly 2 decimal places
        data_two_decimals = {"terminal_id_code": "T1", "amount": "10.99", "currency": "USD"}
        serializer_two_decimals = POSAcquiringTransactionRequestSerializer(data=data_two_decimals)
        self.assertTrue(serializer_two_decimals.is_valid(), serializer_two_decimals.errors)
        self.assertEqual(serializer_two_decimals.validated_data['amount'], Decimal('10.99'))
        
        # Test integer amount
        data_int_amount = {"terminal_id_code": "T1", "amount": "150", "currency": "USD"}
        serializer_int_amount = POSAcquiringTransactionRequestSerializer(data=data_int_amount)
        self.assertTrue(serializer_int_amount.is_valid(), serializer_int_amount.errors)
        self.assertEqual(serializer_int_amount.validated_data['amount'], Decimal('150.00'))


    def test_invalid_currency(self):
        data = {"terminal_id_code": "T1", "amount": "50.00", "currency": "EUR"}
        serializer = POSAcquiringTransactionRequestSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('currency', serializer.errors)
        self.assertEqual(str(serializer.errors['currency'][0]), "Currently, only USD currency is supported.")

    def test_valid_currency_case_insensitivity(self):
        data = {"terminal_id_code": "T1", "amount": "50.00", "currency": "usd"}
        serializer = POSAcquiringTransactionRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data['currency'], "USD")

    def test_pan_last_four_valid(self):
        data = {"terminal_id_code": "T1", "amount": "10.00", "pan_last_four": "1234"}
        serializer = POSAcquiringTransactionRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data['pan_last_four'], "1234")

    def test_pan_last_four_invalid_length(self):
        data = {"terminal_id_code": "T1", "amount": "10.00", "pan_last_four": "123"}
        serializer = POSAcquiringTransactionRequestSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('pan_last_four', serializer.errors)
        self.assertEqual(str(serializer.errors['pan_last_four'][0]), "PAN last four must be 4 digits.")

    def test_pan_last_four_invalid_characters(self):
        data = {"terminal_id_code": "T1", "amount": "10.00", "pan_last_four": "123a"}
        serializer = POSAcquiringTransactionRequestSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('pan_last_four', serializer.errors)
        self.assertEqual(str(serializer.errors['pan_last_four'][0]), "PAN last four must be 4 digits.")
        
    def test_pan_last_four_optional_and_blank(self):
        data = {
            "terminal_id_code": "TERM001",
            "amount": "100.50",
            "currency": "USD",
            "pan_last_four": "" # Blank
        }
        serializer = POSAcquiringTransactionRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data.get('pan_last_four'), "")

    def test_pan_last_four_optional_and_none(self):
        # Note: DRF serializers typically convert None for CharField to empty string if allow_null=False (default)
        # If allow_null=True was set on serializer field, then None would be preserved.
        # Here, it's not explicitly set, so it defaults to allow_blank=True, allow_null=False.
        # An empty string is valid if allow_blank=True.
        data = {
            "terminal_id_code": "TERM001",
            "amount": "100.50",
            "currency": "USD",
            # pan_last_four is omitted
        }
        serializer = POSAcquiringTransactionRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertNotIn('pan_last_four', serializer.validated_data) # Or it might be None or "" depending on exact field definition

    def test_entry_mode_valid(self):
        valid_modes = [choice[0] for choice in POSTransactionData.ENTRY_MODES]
        for mode in valid_modes:
            data = {
                "terminal_id_code": "T1", 
                "amount": "10.00", 
                "entry_mode": mode
            }
            serializer = POSAcquiringTransactionRequestSerializer(data=data)
            self.assertTrue(serializer.is_valid(), f"Failed for entry_mode: {mode}. Errors: {serializer.errors}")
            self.assertEqual(serializer.validated_data['entry_mode'], mode)

    def test_entry_mode_invalid(self):
        data = {"terminal_id_code": "T1", "amount": "10.00", "entry_mode": "INVALID_MODE"}
        serializer = POSAcquiringTransactionRequestSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('entry_mode', serializer.errors)
        self.assertTrue(f"\\\"INVALID_MODE\\\" is not a valid choice." in str(serializer.errors['entry_mode'][0]))
        
    def test_entry_mode_optional_and_blank(self):
        data = {
            "terminal_id_code": "TERM001",
            "amount": "100.50",
            "currency": "USD",
            "entry_mode": "" # Blank
        }
        serializer = POSAcquiringTransactionRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data.get('entry_mode'), "")

    def test_all_optional_fields_omitted(self):
        data = {
            "terminal_id_code": "TERM001",
            "amount": "100.50",
            "currency": "USD",
        }
        serializer = POSAcquiringTransactionRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertNotIn('emv_tags', serializer.validated_data)
        self.assertNotIn('card_brand', serializer.validated_data)
        self.assertNotIn('pan_last_four', serializer.validated_data)
        self.assertNotIn('entry_mode', serializer.validated_data)


class POSTerminalSerializerTests(TestCase):
    def setUp(self):
        self.merchant_user = User.objects.create_user(
            username='merchant_serializer_user',
            password='testpassword123',
            email='merchant_serializer@example.com'
        )
        self.merchant_account = Accounts.objects.create(
            user=self.merchant_user,
            account_name='Merchant Account for Serializer',
            balance=Decimal('2000.00')
        )
        self.api_key_instance, self.api_key_value = APIKey.objects.create_key(
            name='Test POS API Key For Serializer',
            user=self.merchant_user,
            permissions=['pos_terminal_access']
        )
        self.inactive_api_key_instance, _ = APIKey.objects.create_key(
            name='Inactive Key Serializer',
            user=self.merchant_user,
            is_active=False
        )

        self.valid_data = {
            "terminal_id_code": "TERM_SERIALIZER_001",
            "merchant_account_id": str(self.merchant_account.id),
            "api_key_id": str(self.api_key_instance.id),
            "name": "Main Counter Serializer",
            "location": "Store Front Serializer",
            "is_active": True
        }

    def test_valid_data_serialization_create(self):
        serializer = POSTerminalSerializer(data=self.valid_data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        terminal = serializer.save() # Calls serializer.create()
        self.assertIsNotNone(terminal.id)
        self.assertEqual(terminal.terminal_id_code, self.valid_data["terminal_id_code"])
        self.assertEqual(terminal.merchant_account, self.merchant_account)
        self.assertEqual(terminal.api_key, self.api_key_instance)
        self.assertEqual(terminal.name, self.valid_data["name"])
        self.assertEqual(terminal.location, self.valid_data["location"])
        self.assertTrue(terminal.is_active)

        # Test serialized output
        serialized_output = POSTerminalSerializer(terminal).data
        self.assertEqual(serialized_output['terminal_id_code'], self.valid_data["terminal_id_code"])
        self.assertIn('merchant_account_details', serialized_output)
        self.assertEqual(serialized_output['merchant_account_details']['id'], str(self.merchant_account.id))
        self.assertEqual(serialized_output['api_key_id'], str(self.api_key_instance.id))


    def test_missing_required_fields(self):
        invalid_data = {"name": "Only Name Provided"}
        serializer = POSTerminalSerializer(data=invalid_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('terminal_id_code', serializer.errors)
        self.assertIn('merchant_account_id', serializer.errors)

    def test_invalid_merchant_account_id(self):
        data = self.valid_data.copy()
        data['merchant_account_id'] = str(uuid.uuid4()) # Non-existent UUID
        serializer = POSTerminalSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('merchant_account_id', serializer.errors)
        self.assertEqual(str(serializer.errors['merchant_account_id'][0]), "Merchant account does not exist.")

    def test_invalid_api_key_id_non_existent(self):
        data = self.valid_data.copy()
        data['api_key_id'] = str(uuid.uuid4()) # Non-existent UUID
        serializer = POSTerminalSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('api_key_id', serializer.errors)
        self.assertEqual(str(serializer.errors['api_key_id'][0]), "Active API key with this ID does not exist.")

    def test_invalid_api_key_id_inactive(self):
        data = self.valid_data.copy()
        data['api_key_id'] = str(self.inactive_api_key_instance.id)
        serializer = POSTerminalSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('api_key_id', serializer.errors)
        self.assertEqual(str(serializer.errors['api_key_id'][0]), "Active API key with this ID does not exist.")

    def test_optional_api_key_id_null(self):
        data = self.valid_data.copy()
        data['api_key_id'] = None
        serializer = POSTerminalSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        terminal = serializer.save()
        self.assertIsNone(terminal.api_key)

    def test_optional_api_key_id_omitted(self):
        data = self.valid_data.copy()
        del data['api_key_id']
        serializer = POSTerminalSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        terminal = serializer.save()
        self.assertIsNone(terminal.api_key)
        
    def test_read_only_fields(self):
        terminal = POSTerminal.objects.create(
            terminal_id_code='RO_TERM01',
            merchant_account=self.merchant_account,
            name='Read Only Test Terminal'
        )
        data = POSTerminalSerializer(terminal).data
        self.assertIn('id', data)
        self.assertIn('created_at', data)
        self.assertIn('updated_at', data)
        self.assertIn('merchant_account_details', data)
        self.assertEqual(data['merchant_account_details']['account_name'], self.merchant_account.account_name)

    def test_update_terminal(self):
        terminal = POSTerminal.objects.create(
            terminal_id_code='UPDATE_ME',
            merchant_account=self.merchant_account,
            name='Original Name'
        )
        update_data = {
            "name": "Updated Name",
            "location": "New Location",
            "is_active": False
        }
        # Note: For partial updates, use partial=True. Here we are doing a full update of allowed fields.
        # 'terminal_id_code' and 'merchant_account_id' are usually not updatable or handled carefully.
        # The serializer definition implies they are part of creation.
        # Let's assume we are updating fields that are typically updatable.
        serializer = POSTerminalSerializer(terminal, data=update_data, partial=True)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        updated_terminal = serializer.save()
        self.assertEqual(updated_terminal.name, "Updated Name")
        self.assertEqual(updated_terminal.location, "New Location")
        self.assertFalse(updated_terminal.is_active)
        self.assertEqual(updated_terminal.terminal_id_code, 'UPDATE_ME') # Should not change


class POSTransactionDataSerializerTests(TestCase):
    def setUp(self):
        self.merchant_user = User.objects.create_user(
            username='merchant_tx_data_serializer_user',
            password='testpassword123'
        )
        self.merchant_account = Accounts.objects.create(
            user=self.merchant_user,
            account_name='Merchant Account for Tx Data Serializer',
            balance=Decimal('100.00')
        )
        self.transaction = Transactions.objects.create(
            to_account=self.merchant_account,
            amount=Decimal('25.50'),
            transaction_type='POS_SALE',
            description='Test POS Sale for Data Serializer'
        )
        self.pos_data_instance = POSTransactionData.objects.create(
            transaction=self.transaction,
            emv_tags='TEST_EMV_TAGS_SERIALIZER',
            card_brand='MASTERCARD_SERIALIZER',
            pan_last_four='9876',
            authorization_code='AUTH_CODE_SERIALIZER',
            entry_mode='SWIPE'
        )

    def test_serialize_pos_transaction_data_instance(self):
        serializer = POSTransactionDataSerializer(self.pos_data_instance)
        data = serializer.data

        self.assertIn('id', data)
        self.assertEqual(data['id'], str(self.pos_data_instance.id))
        self.assertIn('transaction_id', data)
        self.assertEqual(data['transaction_id'], str(self.transaction.id))
        self.assertEqual(data['emv_tags'], 'TEST_EMV_TAGS_SERIALIZER')
        self.assertEqual(data['card_brand'], 'MASTERCARD_SERIALIZER')
        self.assertEqual(data['pan_last_four'], '9876')
        self.assertEqual(data['authorization_code'], 'AUTH_CODE_SERIALIZER')
        self.assertEqual(data['entry_mode'], 'SWIPE')
        self.assertIn('created_at', data)

    def test_transaction_id_is_read_only(self):
        # Attempting to provide transaction_id during deserialization should be ignored
        # as it's read-only and sourced from the instance.
        # This serializer is primarily for output.
        # If we were to try to create/update via this serializer (which is not its typical use case),
        # read_only fields would not be accepted as input.
        
        # Let's verify the field is marked read_only in the serializer's meta
        serializer_fields = POSTransactionDataSerializer().get_fields()
        self.assertTrue(serializer_fields['transaction_id'].read_only)
        self.assertTrue(serializer_fields['id'].read_only)
        self.assertTrue(serializer_fields['created_at'].read_only)

    def test_all_fields_present_in_serialization(self):
        serializer = POSTransactionDataSerializer(self.pos_data_instance)
        data = serializer.data
        expected_keys = [
            'id', 'transaction_id', 'emv_tags', 'card_brand', 
            'pan_last_four', 'authorization_code', 'entry_mode', 'created_at'
        ]
        for key in expected_keys:
            self.assertIn(key, data)


class POSAcquiringViewTests(APITestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.merchant_user = User.objects.create_user(
            username='merchant_view_user',
            password='testpassword123',
            email='merchant_view@example.com'
        )
        self.merchant_account = Accounts.objects.create(
            user=self.merchant_user,
            account_name='Merchant Account for View Tests',
            balance=Decimal('1000.00'),
            currency='USD'
        )
        # Create an APIKey and link it to the user who owns the merchant account
        self.api_key_instance, self.api_key_value = APIKey.objects.create_key(
            name='Test POS API Key For View',
            user=self.merchant_user, # Key associated with the merchant user
            permissions=['pos_terminal_access']
        )
        self.pos_terminal = POSTerminal.objects.create(
            terminal_id_code='VIEWTEST001',
            merchant_account=self.merchant_account,
            api_key=self.api_key_instance, # Link the API key here
            name='View Test Terminal',
            is_active=True
        )
        self.inactive_pos_terminal = POSTerminal.objects.create(
            terminal_id_code='VIEWTEST002_INACTIVE',
            merchant_account=self.merchant_account,
            api_key=self.api_key_instance, # Can use the same key for testing this scenario
            name='View Test Terminal Inactive',
            is_active=False
        )

        self.valid_payload = {
            "terminal_id_code": self.pos_terminal.terminal_id_code, # This is used by serializer, not directly by view logic for auth
            "amount": "125.75",
            "currency": "USD",
            "emv_tags": "test_emv_data_view",
            "card_brand": "VISA_VIEW",
            "pan_last_four": "4321",
            "entry_mode": "TAP_TO_PAY"
        }

    def _make_request(self, payload, api_key_value=None):
        request = self.factory.post('/api/pos/acquire/', payload, format='json')
        if api_key_value:
            request.META['HTTP_AUTHORIZATION'] = f'ApiKey {api_key_value}'
        
        # Simulate APIKeyAuthenticationMiddleware setting these attributes
        # This is crucial for IsPOSTerminal permission to work correctly
        if api_key_value:
            try:
                key_instance = APIKey.objects.get_from_key(api_key_value)
                request.user = APIKeyUser() # Simulate APIKeyUser
                request.auth = api_key_value
                request.api_key = key_instance # Attach the APIKey instance
            except APIKey.DoesNotExist:
                request.user = User() # AnonymousUser or a basic User for unauth
                request.auth = None
                request.api_key = None
        else: # No API key provided
            request.user = User() 
            request.auth = None
            request.api_key = None
            
        return request

    @patch('main.services.POSService.acquire_transaction')
    def test_successful_pos_acquisition(self, mock_acquire_transaction):
        # Mock the service layer
        mock_transaction = MagicMock(spec=Transactions)
        mock_transaction.id = uuid.uuid4()
        mock_transaction.amount = Decimal(self.valid_payload['amount'])
        # ... add other fields if TransactionDetailSerializer needs them
        mock_acquire_transaction.return_value = mock_transaction

        # Mock the TransactionDetailSerializer
        mock_serializer_instance = MagicMock()
        mock_serializer_instance.data = {'id': str(mock_transaction.id), 'amount': self.valid_payload['amount']}


        with patch('main.views_pos.TransactionDetailSerializer', return_value=mock_serializer_instance) as mock_transaction_serializer_class:
            request = self._make_request(self.valid_payload, self.api_key_value)
            
            # Manually run permission check or ensure middleware does
            # For APITestCase, permissions are usually run.
            # We need to ensure request.pos_terminal is set by IsPOSTerminal
            # This happens if API key is valid and linked to an active terminal.
            # Our _make_request and setUp ensure this for self.api_key_value

            view = POSAcquiringView.as_view()
            response = view(request)

            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertIn('message', response.data)
            self.assertEqual(response.data['message'], 'POS transaction acquired successfully.')
            self.assertIn('data', response.data)
            # self.assertEqual(response.data['data']['id'], str(mock_transaction.id)) # Check serializer output

            mock_acquire_transaction.assert_called_once_with(
                validated_data=self.valid_payload, # Serializer passes validated data
                merchant_account=self.merchant_account,
                pos_terminal=self.pos_terminal
            )
            mock_transaction_serializer_class.assert_called_once_with(mock_transaction)


    def test_pos_acquisition_invalid_payload(self):
        payload = self.valid_payload.copy()
        del payload['amount'] # Missing required field
        request = self._make_request(payload, self.api_key_value)
        view = POSAcquiringView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Invalid request data.')
        self.assertIn('details', response.data)
        self.assertIn('amount', response.data['details'])

    def test_pos_acquisition_no_api_key(self):
        request = self._make_request(self.valid_payload, api_key_value=None)
        view = POSAcquiringView.as_view()
        response = view(request)
        # IsPOSTerminal permission should deny access
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED) # Or 403 depending on default handler
        self.assertIn('detail', response.data) # DRF default error key for auth
        self.assertEqual(str(response.data['detail']), "Authentication credentials were not provided.")


    def test_pos_acquisition_invalid_api_key(self):
        request = self._make_request(self.valid_payload, api_key_value="invalidkey123")
        view = POSAcquiringView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED) # Or 403
        self.assertIn('detail', response.data)
        # The message comes from APIKeyAuthentication in DRF-APIKey if key is malformed or not found
        # If key is found but IsPOSTerminal fails, message is from IsPOSTerminal
        # In this case, APIKey.DoesNotExist will be raised in _make_request, so request.auth is None
        self.assertEqual(str(response.data['detail']), "Authentication credentials were not provided.")


    def test_pos_acquisition_api_key_not_linked_to_active_terminal(self):
        # Create a new key not linked to any POSTerminal
        unlinked_api_key_instance, unlinked_api_key_value = APIKey.objects.create_key(
            name='Unlinked Key For View', user=self.merchant_user
        )
        request = self._make_request(self.valid_payload, unlinked_api_key_value)
        view = POSAcquiringView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('detail', response.data)
        self.assertEqual(str(response.data['detail']), "API key is not associated with an active POS terminal.")

    def test_pos_acquisition_terminal_inactive(self):
        # Use an API key that IS linked, but to an INACTIVE terminal
        # We need a new API key for the inactive terminal, or re-assign existing one if one-to-one
        # For this test, let\'s assume the inactive_pos_terminal uses the same API key for simplicity
        # The IsPOSTerminal permission should catch this.
        
        # To make this test robust, ensure the inactive terminal has its own key
        # or that the shared key correctly identifies the active/inactive state.
        # If POSTerminal.api_key is ForeignKey, multiple terminals can share a key (less secure).
        # If OneToOneField, then each terminal needs a unique active key.
        # The current setup has api_key as ForeignKey in POSTerminal model.
        # The IsPOSTerminal permission checks POSTerminal.objects.get(api_key=api_key_instance, is_active=True)
        # So, if the key is linked to an active terminal (self.pos_terminal) AND an inactive one (self.inactive_pos_terminal),
        # the permission will likely find the active one and pass.
        # To test this properly, we need an API key that is *only* linked to an inactive terminal.

        dedicated_inactive_key_instance, dedicated_inactive_key_value = APIKey.objects.create_key(
            name='Dedicated Inactive Key', user=self.merchant_user
        )
        self.inactive_pos_terminal.api_key = dedicated_inactive_key_instance
        self.inactive_pos_terminal.save()

        request = self._make_request(self.valid_payload, dedicated_inactive_key_value)
        view = POSAcquiringView.as_view()
        response = view(request)
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('detail', response.data)
        self.assertEqual(str(response.data['detail']), "API key is not associated with an active POS terminal.")


    @patch('main.services.POSService.acquire_transaction')
    def test_pos_acquisition_service_layer_exception(self, mock_acquire_transaction):
        mock_acquire_transaction.side_effect = Exception("Service layer boom!")
        
        request = self._make_request(self.valid_payload, self.api_key_value)
        view = POSAcquiringView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Failed to process POS transaction.')
        self.assertIn('details', response.data) # Generic message for production
        self.assertEqual(response.data['details'], 'An internal error occurred.')
        mock_acquire_transaction.assert_called_once()

    def test_pos_acquisition_terminal_id_mismatch_in_payload(self):
        # Even if API key is valid and linked to self.pos_terminal,
        # the payload might contain a different terminal_id_code.
        # The serializer validates this field, but the view logic primarily relies on request.pos_terminal from IsPOSTerminal.
        # This test ensures the request.pos_terminal (derived from API key) is used.
        payload = self.valid_payload.copy()
        payload['terminal_id_code'] = "DIFFERENT_TERM_ID" 

        with patch('main.services.POSService.acquire_transaction') as mock_acquire_transaction:
            mock_transaction = MagicMock(spec=Transactions)
            mock_transaction.id = uuid.uuid4()
            mock_acquire_transaction.return_value = mock_transaction
            
            mock_serializer_instance = MagicMock()
            mock_serializer_instance.data = {'id': str(mock_transaction.id), 'amount': self.valid_payload['amount']}

            with patch('main.views_pos.TransactionDetailSerializer', return_value=mock_serializer_instance):
                request = self._make_request(payload, self.api_key_value)
                view = POSAcquiringView.as_view()
                response = view(request)

                self.assertEqual(response.status_code, status.HTTP_201_CREATED)
                mock_acquire_transaction.assert_called_once()
                # Crucially, check that the pos_terminal passed to the service is the one from the API key, not the payload.
                called_args, called_kwargs = mock_acquire_transaction.call_args
                self.assertEqual(called_kwargs['pos_terminal'], self.pos_terminal)
                self.assertEqual(called_kwargs['validated_data']['terminal_id_code'], "DIFFERENT_TERM_ID")


    @patch('main.views_pos.logger') # Patch the logger in views_pos
    def test_logging_on_invalid_request(self, mock_logger):
        payload = self.valid_payload.copy()
        del payload['amount'] # Invalid
        request = self._make_request(payload, self.api_key_value)
        view = POSAcquiringView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        mock_logger.warning.assert_called_once()
        args, _ = mock_logger.warning.call_args
        self.assertIn("Invalid POS acquiring request", args[0])

    @patch('main.views_pos.logger')
    @patch('main.services.POSService.acquire_transaction', side_effect=Exception("Service Error"))
    def test_logging_on_service_error(self, mock_service, mock_logger):
        request = self._make_request(self.valid_payload, self.api_key_value)
        view = POSAcquiringView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        mock_logger.error.assert_called_once()
        args, _ = mock_logger.error.call_args
        self.assertIn("Error processing POS transaction for terminal", args[0])
        self.assertEqual(args[1], self.pos_terminal.terminal_id_code) # Check terminal ID is logged
        self.assertEqual(args[2], "Service Error") # Check exception message is logged
