from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import Profile, Accounts, Transactions, RecurringPayment, APIKey, APIKeyUsage

class ProfileAdmin(UserAdmin):
    # Add fields for Profile to admin interface
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2', 'first_name', 'family_name', 'last_name'),
        }),
    )
    
    # Fields to display in admin list view
    list_display = ('username', 'first_name', 'family_name', 'last_name', 'is_active', 'is_staff')
    
    # Filter options
    list_filter = ('is_staff', 'is_superuser', 'is_active')
    
    # Search fields
    search_fields = ('username', 'first_name', 'family_name', 'last_name')
    
    # Fields to show when editing a user
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'family_name', 'last_name')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
        ('Accounts', {'fields': ('accounts',)}),
    )

@admin.register(RecurringPayment)
class RecurringPaymentAdmin(admin.ModelAdmin):
    list_display = ('id', 'withdraw_account', 'credit_account', 'amount', 'frequency', 'status', 'next_payment_date', 'total_payments_made')
    list_filter = ('frequency', 'status', 'created_at')
    search_fields = ('withdraw_account__name', 'credit_account__name', 'message')
    readonly_fields = ('id', 'total_payments_made', 'last_payment_date', 'created_at', 'updated_at')
    
    fieldsets = (
        ('Payment Details', {
            'fields': ('withdraw_account', 'credit_account', 'amount', 'message')
        }),
        ('Schedule', {
            'fields': ('frequency', 'start_date', 'next_payment_date', 'end_date')
        }),
        ('Limits', {
            'fields': ('max_payments', 'status')
        }),
        ('Tracking', {
            'fields': ('total_payments_made', 'last_payment_date'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('id', 'created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'withdraw_account', 'credit_account', 'created_by'
        )

@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'user', 'permissions', 'is_active', 'created_at', 'expires_at', 'last_used_at')
    list_filter = ('is_active', 'permissions', 'created_at', 'expires_at')
    search_fields = ('name', 'user__username')
    readonly_fields = ('id', 'key', 'user', 'created_at', 'last_used_at') # 'key' is already editable=False in model
    
    fieldsets = (
        ('API Key Details', {
            'fields': ('id', 'name', 'user', 'permissions', 'scopes', 'allowed_ips', 'is_active', 'created_at', 'last_used_at', 'expires_at')
        }),
    )

    def has_add_permission(self, request):
        # API keys should only be created via the API, not admin
        return False

@admin.register(APIKeyUsage)
class APIKeyUsageAdmin(admin.ModelAdmin):
    list_display = ('id', 'api_key', 'timestamp', 'ip_address', 'method', 'path', 'status_code', 'response_time_ms')
    list_filter = ('status_code', 'timestamp', 'api_key')
    search_fields = ('api_key__name', 'ip_address', 'path')
    readonly_fields = ('id', 'api_key', 'timestamp', 'ip_address', 'user_agent', 'method', 'path', 'status_code', 'response_time_ms', 'request_size', 'response_size', 'error_message')
    
    fieldsets = (
        ('Usage Details', {
            'fields': ('id', 'api_key', 'timestamp', 'ip_address', 'user_agent', 'method', 'path', 'status_code', 'response_time_ms', 'request_size', 'response_size', 'error_message')
        }),
    )

    def has_add_permission(self, request):
        # Usage logs are created automatically
        return False

admin.site.register(Profile, ProfileAdmin)
admin.site.register(Accounts)
admin.site.register(Transactions)
