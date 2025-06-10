from django.db import models
import uuid
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta # Import timedelta
import math
from django.conf import settings # Added import

class Profile(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, verbose_name="ProfileID")
    first_name = models.TextField(verbose_name="FirstName")
    family_name = models.TextField(verbose_name="FamilyName") # Corrected Typo: FamilytName -> FamilyName
    last_name = models.TextField(verbose_name="LastName")

    # 2FA Fields
    two_factor_enabled = models.BooleanField(default=False, verbose_name="2FA Enabled")
    two_factor_secret = models.CharField(max_length=32, blank=True, null=True, verbose_name="2FA Secret")
    backup_codes = models.JSONField(default=list, blank=True, verbose_name="Backup Codes")
    last_totp_used = models.CharField(max_length=6, blank=True, null=True, verbose_name="Last TOTP Used")
    two_factor_enabled_at = models.DateTimeField(null=True, blank=True, verbose_name="2FA Enabled At")
    # Add missing fields for 2FA API compatibility
    two_factor_enabled_date = models.DateTimeField(null=True, blank=True, verbose_name="2FA Enabled Date")
    two_factor_setup_date = models.DateTimeField(null=True, blank=True, verbose_name="2FA Setup Date")
    two_factor_disabled_date = models.DateTimeField(null=True, blank=True, verbose_name="2FA Disabled Date")

    accounts = models.ManyToManyField('Accounts', related_name='profile', verbose_name="Accounts")

    def __str__(self):
        return f"{self.first_name} {self.family_name} {self.last_name}"

class Accounts(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, verbose_name="AccountID")
    balance = models.DecimalField(max_digits=19, decimal_places=4, default=0.0000, verbose_name="Balance") # Changed to DecimalField for precision
    name = models.TextField(verbose_name="AccountName")
    public_key = models.TextField(verbose_name="PublicKey", default="test")

    def __str__(self):
        return str(self.name) # Changed from self.id to self.name for better readability

class Transactions(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    from_account = models.ForeignKey(Accounts, related_name='sent_transactions', on_delete=models.CASCADE, null=True, blank=True)
    to_account = models.ForeignKey(Accounts, related_name='received_transactions', on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='USD')
    TRANSACTION_TYPES = [
        ('TRANSFER', 'Transfer'),
        ('RECURRING', 'Recurring Payment'),
        ('POS_SALE', 'Point of Sale Sale'),
        ('FEE', 'Fee'),
        ('REFUND', 'Refund'),
    ]
    transaction_type = models.CharField(max_length=50, choices=TRANSACTION_TYPES, default='TRANSFER')
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
        ('CANCELLED', 'Cancelled'),
        ('REVERSED', 'Reversed'),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    description = models.TextField(blank=True, null=True)
    created_by = models.ForeignKey('Profile', on_delete=models.SET_NULL, null=True, blank=True, related_name='created_transactions')


    def __str__(self):
        return f"Transaction {self.id} - {self.amount} {self.currency} - {self.status}"

class RecurringPayment(models.Model):
    FREQUENCY_CHOICES = [
        ('DAILY', 'Daily'),
        ('WEEKLY', 'Weekly'),
        ('MONTHLY', 'Monthly'),
        ('YEARLY', 'Yearly'),
    ]
    
    STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('PAUSED', 'Paused'),
        ('CANCELLED', 'Cancelled'),
        ('COMPLETED', 'Completed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, verbose_name="RecurringPaymentID")
    withdraw_account = models.ForeignKey("Accounts", related_name='recurring_withdrawals', on_delete=models.CASCADE)
    credit_account = models.ForeignKey("Accounts", related_name='recurring_credits', on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2, verbose_name="Amount") # Changed to DecimalField
    message = models.TextField(verbose_name="Message")
    frequency = models.CharField(max_length=10, choices=FREQUENCY_CHOICES, verbose_name="Frequency")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='ACTIVE', verbose_name="Status")
    
    # Date fields
    start_date = models.DateTimeField(verbose_name="Start Date")
    next_payment_date = models.DateTimeField(verbose_name="Next Payment Date")
    end_date = models.DateTimeField(null=True, blank=True, verbose_name="End Date")
    
    # Tracking fields
    total_payments_made = models.IntegerField(default=0, verbose_name="Total Payments Made")
    max_payments = models.IntegerField(null=True, blank=True, verbose_name="Maximum Payments")
    last_payment_date = models.DateTimeField(null=True, blank=True, verbose_name="Last Payment Date")
    
    # Metadata
    created_by = models.ForeignKey(Profile, on_delete=models.CASCADE, verbose_name="Created By")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Created At")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Updated At")
    
    def __str__(self):
        # Ensure withdraw_account and credit_account are not None before accessing name
        withdraw_name = self.withdraw_account.name if self.withdraw_account else "N/A"
        credit_name = self.credit_account.name if self.credit_account else "N/A"
        return f"Recurring payment: {self.amount} from {withdraw_name} to {credit_name} ({self.frequency})"
    
    def calculate_next_payment_date(self):
        """Calculate the next payment date based on frequency"""
        if self.frequency == 'DAILY':
            return self.next_payment_date + timedelta(days=1)
        elif self.frequency == 'WEEKLY':
            return self.next_payment_date + timedelta(weeks=1)
        elif self.frequency == 'MONTHLY':
            # Add one month (approximately 30 days for simplicity)
            return self.next_payment_date + timedelta(days=30)
        elif self.frequency == 'YEARLY':
            return self.next_payment_date + timedelta(days=365)
        return self.next_payment_date
    
    def is_due_for_payment(self):
        """Check if the recurring payment is due"""
        return (
            self.status == 'ACTIVE' and
            self.next_payment_date <= timezone.now() and
            (not self.end_date or self.next_payment_date <= self.end_date) and
            (not self.max_payments or self.total_payments_made < self.max_payments)
        )
    
    def should_be_completed(self):
        """Check if the recurring payment should be marked as completed"""
        return (
            (self.end_date and timezone.now() > self.end_date) or
            (self.max_payments and self.total_payments_made >= self.max_payments)
        )

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Recurring Payment"
        verbose_name_plural = "Recurring Payments"


class AuditLog(models.Model):
    """
    Comprehensive audit log for all financial operations.
    """
    ACTION_CHOICES = [
        ('CREATE', 'Create'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('TRANSFER', 'Transfer'),
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('VIEW', 'View'),
        ('AUTHORIZE', 'Authorize'),
        ('REJECT', 'Reject'),
    ]
    
    CATEGORY_CHOICES = [
        ('AUTH', 'Authentication'),
        ('ACCOUNT', 'Account Management'),
        ('TRANSACTION', 'Transaction'),
        ('RECURRING', 'Recurring Payment'),
        ('USER', 'User Management'),
        ('SECURITY', 'Security Event'),
        ('SYSTEM', 'System Event'),
    ]
    
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    
    # User information
    user = models.ForeignKey(Profile, on_delete=models.SET_NULL, null=True, blank=True)
    username = models.CharField(max_length=150, blank=True)
    
    # Action details
    action = models.CharField(max_length=20, choices=ACTION_CHOICES, db_index=True)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, db_index=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='MEDIUM', db_index=True)
    
    # Request details
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    request_method = models.CharField(max_length=10, blank=True)
    request_path = models.CharField(max_length=500, blank=True)
    
    # Object reference
    object_type = models.CharField(max_length=50, blank=True)  # Store model name
    object_id = models.CharField(max_length=100, blank=True)   # Store object ID
    
    # Additional details
    description = models.TextField()
    old_values = models.JSONField(default=dict, blank=True)
    new_values = models.JSONField(default=dict, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    # Result
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp', 'category']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['severity', 'timestamp']),
            models.Index(fields=['success', 'timestamp']),
        ]
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"
    
    def __str__(self):
        return f"{self.timestamp} - {self.category}: {self.description}"

class APIKey(models.Model):
    key = models.CharField(max_length=255, unique=True, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='api_keys') # Changed to settings.AUTH_USER_MODEL
    name = models.CharField(max_length=100, help_text="A descriptive name for the API key.")
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    # Permissions related to the API key
    PERMISSION_CHOICES = [
        ('read_only', 'Read Only'),
        ('read_write', 'Read and Write'),
        ('pos_terminal', 'POS Terminal Access'), # Added for POS
        ('full_access', 'Full Access'),
    ]
    permissions = models.CharField(
        max_length=20,
        choices=PERMISSION_CHOICES,
        default='read_only', # Changed default to a valid choice
        help_text="Permissions granted to this API key."
    )

    # Scope: what parts of the API this key can access (e.g., 'transactions', 'accounts')
    # For simplicity, using a comma-separated string. A ManyToManyField to a Scope model would be more robust.
    scopes = models.TextField(blank=True, help_text="Comma-separated list of access scopes (e.g., 'transactions:read,accounts:write').")

    # IP Whitelisting: restrict key usage to specific IP addresses
    # For simplicity, using a comma-separated string.
    allowed_ips = models.TextField(blank=True, help_text="Comma-separated list of allowed IP addresses. Leave blank to allow any IP.")

    def __str__(self):
        return f"{self.name} ({self.user.username}) - {'Active' if self.is_active else 'Inactive'}"

    def is_valid(self):
        if not self.is_active:
            return False
        if self.expires_at and self.expires_at < timezone.now():
            return False
        return True

    def has_scope(self, scope):
        """Checks if the API key has a specific scope."""
        if not self.scopes: # If no scopes are defined, assume no access unless it's a super-key or similar logic
            return False
        return scope in self.scopes.split(',')

    def check_ip(self, ip_address):
        """Checks if the given IP address is allowed."""
        if not self.allowed_ips: # If no IPs are whitelisted, allow all
            return True
        return str(ip_address) in [ip.strip() for ip in self.allowed_ips.split(',')]

class APIKeyUsage(models.Model):
    """
    Track API key usage for rate limiting and analytics.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    api_key = models.ForeignKey(APIKey, on_delete=models.CASCADE, related_name='usage_logs')
    
    # Request details
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    method = models.CharField(max_length=10)
    path = models.CharField(max_length=500)
    
    # Response details
    status_code = models.IntegerField()
    response_time_ms = models.IntegerField(null=True, blank=True)
    
    # Additional metadata
    request_size = models.IntegerField(null=True, blank=True)
    response_size = models.IntegerField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['api_key', 'timestamp']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
        ]
        verbose_name = "API Key Usage"
        verbose_name_plural = "API Key Usage Logs"
    
    def __str__(self):
        return f"{self.api_key.name} - {self.method} {self.path} ({self.status_code})"

class POSTerminal(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    terminal_id_code = models.CharField(max_length=100, unique=True, help_text="Unique identifier for the POS terminal hardware/software.")
    merchant_account = models.ForeignKey(Accounts, on_delete=models.CASCADE, related_name='pos_terminals')
    api_key = models.OneToOneField(APIKey, on_delete=models.SET_NULL, null=True, blank=True, related_name='pos_terminal', help_text="API key associated with this terminal for authentication.")
    is_active = models.BooleanField(default=True)
    name = models.CharField(max_length=255, blank=True, null=True, help_text="Human-readable name for the terminal (e.g., 'Front Counter').")
    location = models.CharField(max_length=255, blank=True, null=True, help_text="Physical location of the terminal.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name or self.terminal_id_code} ({self.merchant_account.name})" # Changed account_name to name

class POSTransactionData(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    transaction = models.OneToOneField(Transactions, on_delete=models.CASCADE, related_name='pos_data')
    terminal = models.ForeignKey(POSTerminal, on_delete=models.SET_NULL, null=True, blank=True, help_text="The POS terminal used for this transaction")
    emv_tags = models.JSONField(blank=True, null=True, help_text="Relevant, non-sensitive EMV tag data (JSON format)")
    card_brand = models.CharField(max_length=50, blank=True, null=True, help_text="Card brand, e.g., Visa, Mastercard")
    pan_last_four = models.CharField(max_length=4, blank=True, null=True, help_text="Last four digits of the Primary Account Number (PAN)")
    authorization_code = models.CharField(max_length=50, blank=True, null=True, help_text="Authorization code from the issuer/acquirer, if applicable")
    entry_mode = models.CharField(max_length=20, blank=True, null=True, help_text="e.g., CHIP, MAGSTRIPE, CONTACTLESS, MANUAL")
    transaction_sequence_counter = models.CharField(max_length=10, blank=True, null=True, help_text="Application Transaction Counter (ATC) or similar sequence number from card")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        # Corrected access to related fields
        terminal_code = self.terminal.terminal_id_code if self.terminal and hasattr(self.terminal, 'terminal_id_code') else 'N/A'
        transaction_id_val = self.transaction.id if self.transaction and hasattr(self.transaction, 'id') else 'N/A'
        return f"POS Data for Transaction {transaction_id_val} - Terminal: {terminal_code}"
