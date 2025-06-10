# GitHub Copilot Instructions for PersifonPay Django Backend

## Project Overview
This is a Django REST API backend for PersifonPay, a payment processing system with support for regular transactions and recurring payments. The system is built using Django 5.1.4 with Django REST Framework.

## Project Structure & Key Apps

### Core Apps
- **`main/`** - Primary payment processing app containing core models and API endpoints
- **`blog/`** - Blog/content management functionality 
- **`applewallet/`** - Apple Wallet integration (placeholder)
- **`ton/`** - TON blockchain integration (placeholder)
- **`pay/`** - Django project root with settings and main URL configuration

### Key Models (main/models.py)
1. **`Profile`** - Custom user model extending AbstractUser
2. **`Accounts`** - User accounts with balance tracking and public keys
3. **`Transactions`** - Individual payment transactions between accounts
4. **`RecurringPayment`** - Automated recurring payment system with scheduling

## Core Features

### Authentication & Authorization
- JWT-based authentication using `djangorestframework-simplejwt`
- Custom permission mixins (`AccountAccessMixin`, `HasAccountAccess`, `HasTransactionAccess`)
- Users can only access their own accounts and transactions

### Payment System
- Account-to-account transfers with balance validation
- Transaction history tracking
- Precision handling with rounding to 2 decimal places using `math.ceil()`

### Recurring Payments System
**Key Features:**
- Flexible scheduling (DAILY, WEEKLY, MONTHLY, YEARLY)
- Status management (ACTIVE, PAUSED, CANCELLED, COMPLETED)
- Optional end dates and payment limits
- Automatic payment processing via management command
- Balance validation before processing

**Important Classes:**
- `RecurringPaymentService` - Service class for business logic
- `process_recurring_payments` management command - Automated processing

### API Endpoints (main/urls.py)
```
/api/profile/ - User profile management
/api/account/ - Account CRUD operations
/api/account/<id>/ - Account details
/api/transactions/<account_id>/ - Transaction history
/api/transaction/ - Create transactions
/api/transaction/<id>/ - Transaction details
/api/recurring-payments/ - Recurring payment CRUD
/api/recurring-payments/<id>/ - Individual recurring payment operations
/api/token/ - JWT token management
```

## Development Guidelines

### Database & Models
- Uses SQLite for development (`db.sqlite3`)
- All models use UUID primary keys
- Custom user model: `AUTH_USER_MODEL = "main.Profile"`
- Related fields use `select_related()` for performance

### API Design Patterns
- Class-based views inheriting from `APIView`
- Consistent error handling with proper HTTP status codes
- JSON request/response format
- Pagination and filtering using `django-filter`

### Business Logic Organization
- Service classes for complex operations (`RecurringPaymentService`)
- Mixins for common functionality (`AccountAccessMixin`)
- Management commands for scheduled tasks

### Key Technical Patterns

**Balance Handling:**
```python
# Always round to 2 decimal places to prevent floating point issues
balance = math.ceil(balance * 100) / 100
```

**Transaction Processing:**
```python
# Use database transactions for atomic operations
with transaction.atomic():
    # Update balances and create transaction records
```

**Date Handling:**
- All dates stored as `DateTimeField` with timezone awareness
- ISO format for API date exchanges
- Use `django.utils.timezone.now()` for current timestamps

### Security Considerations
- JWT tokens with rotation and blacklisting
- Account access validation in all views
- Input validation for all financial operations
- CORS configured for frontend integration

## Dependencies & Configuration

### Key Dependencies
```
Django == 5.1.4
djangorestframework == 3.15.2
djangorestframework-simplejwt == 5.4.0
django-cors-headers == 4.7.0
django-filter == 24.3
django-markdownx == 4.0.7
```

### Environment Setup
- Python 3.12+ required
- SQLite database for development
- CORS enabled for `http://localhost:4200` (Angular frontend)

### Management Commands
```bash
# Process recurring payments (with dry-run option)
python manage.py process_recurring_payments --dry-run
```

## Code Style & Conventions

### Error Handling
- Always return appropriate HTTP status codes
- Include descriptive error messages in JSON format
- Use try-catch blocks for potential failure points

### Validation Patterns
- Validate all financial amounts as positive floats
- Check account access before operations
- Validate date formats using `django.utils.dateparse`

### Response Format
```python
# Success responses
return Response({
    'data': serialized_data,
    'message': 'Operation successful'
}, status=status.HTTP_200_OK)

# Error responses  
return Response({
    'error': 'Description of error'
}, status=status.HTTP_400_BAD_REQUEST)
```

## Testing & Development

### Test Files
- `test_recurring_api.py` - Recurring payment API tests
- `test_recurring_payments.py` - Recurring payment logic tests
- `test_truelove_api.py` - General API tests

### Demo Scripts
- `api_demo.py` - API demonstration script
- `setup_recurring_demo.py` - Recurring payment setup demo

## Common Operations

### Creating Transactions
1. Validate user has access to withdraw account
2. Check sufficient balance
3. Create transaction record
4. Update both account balances atomically

### Managing Recurring Payments
1. Create with validation of accounts and amounts
2. Schedule using `calculate_next_payment_date()`
3. Process using management command
4. Support pause/resume/cancel operations

### Account Management
- Each user can have multiple accounts
- Accounts have names and maintain balances
- Public key storage for future blockchain integration

## Future Considerations
- TON blockchain integration (ton/ app)
- Apple Wallet passes (applewallet/ app)
- Enhanced security features
- Production database migration
- Webhook support for external integrations

## Notes for AI Assistant
- Always validate financial operations for security
- Use atomic database transactions for money transfers
- Respect the existing error handling patterns
- Follow the established authentication/authorization flow
- Consider timezone handling for international usage
- Maintain backwards compatibility when modifying APIs
- Use the service layer pattern for complex business logic
