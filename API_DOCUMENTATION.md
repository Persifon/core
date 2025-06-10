# PersifonPay API Documentation

## Overview

PersifonPay is a Django REST API backend for payment processing with support for regular transactions and recurring payments. The API uses JWT authentication and follows RESTful design principles.

**Base URL:** `http://localhost:8000`  
**Authentication:** JWT Bearer Token  
**Content-Type:** `application/json`

## Table of Contents

- [Authentication](#authentication)
- [User Profile Management](#user-profile-management)
- [Account Management](#account-management)
- [Transaction Management](#transaction-management)
- [Recurring Payments](#recurring-payments)
- [Error Handling](#error-handling)
- [Response Formats](#response-formats)
- [API Key Authentication & Management](#api-key-authentication--management)

---

## Authentication

All authenticated endpoints require a JWT token in the Authorization header:
```
Authorization: Bearer <your_jwt_token>
```

### Obtain Token

**Endpoint:** `POST /api/token/`

**Description:** Authenticate user and obtain JWT access and refresh tokens.

**Request Body:**
```json
{
    "username": "string",
    "password": "string"
}
```

**Response (200 OK):**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

### Refresh Token

**Endpoint:** `POST /api/token/refresh/`

**Description:** Refresh an expired access token using the refresh token.

**Request Body:**
```json
{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Response (200 OK):**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

### Verify Token

**Endpoint:** `POST /api/token/verify/`

**Description:** Verify if a token is valid and not expired.

**Request Body:**
```json
{
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Response (200 OK):** Empty response body indicates token is valid.

---

## User Profile Management

### Get User Profile

**Endpoint:** `GET /api/profile/`

**Description:** Retrieve the current user's profile information including associated accounts.

**Authentication:** Required

**Response (200 OK):**
```json
{
    "id": "uuid",
    "username": "string",
    "first_name": "string",
    "family_name": "string", 
    "last_name": "string",
    "email": "string",
    "is_active": true,
    "accounts": [
        {
            "id": "uuid",
            "name": "string",
            "balance": 0.00,
            "public_key": "string"
        }
    ]
}
```

### Update User Profile

**Endpoint:** `POST /api/profile/`

**Description:** Update the current user's profile information.

**Authentication:** Required

**Request Body:**
```json
{
    "first_name": "string",
    "family_name": "string",
    "last_name": "string"
}
```

**Response (200 OK):**
```json
{
    "message": "ok",
    "profile": {
        "id": "uuid",
        "first_name": "string",
        "family_name": "string",
        "last_name": "string"
    }
}
```

---

## Account Management

### List User Accounts

**Endpoint:** `GET /api/account/`

**Description:** Retrieve all accounts associated with the current user.

**Authentication:** Required

**Response (200 OK):**
```json
[
    {
        "id": "uuid",
        "name": "string",
        "balance": 0.00,
        "public_key": "string"
    }
]
```

### Create Account

**Endpoint:** `POST /api/account/`

**Description:** Create a new account for the current user.

**Authentication:** Required

**Request Body:**
```json
{
    "name": "string",
    "balance": 0.00  // Optional, defaults to 0.0
}
```

**Response (201 Created):**
```json
{
    "id": "uuid",
    "name": "string",
    "balance": 0.00
}
```

### Get Account Details

**Endpoint:** `GET /api/account/{account_id}/`

**Description:** Retrieve details of a specific account. User must have access to this account.

**Authentication:** Required

**Path Parameters:**
- `account_id` (UUID): The ID of the account

**Response (200 OK):**
```json
{
    "id": "uuid",
    "name": "string",
    "balance": 0.00,
    "public_key": "string"
}
```

### Update Account

**Endpoint:** `PUT /api/account/`

**Description:** Update account details. User must have access to the account.

**Authentication:** Required

**Request Body:**
```json
{
    "account_id": "uuid",
    "name": "string",  // Optional
    "balance": 0.00    // Optional
}
```

**Response (200 OK):**
```json
{
    "message": "Account updated successfully",
    "account": {
        "id": "uuid",
        "name": "string",
        "balance": 0.00,
        "public_key": "string"
    }
}
```

### Delete Account

**Endpoint:** `DELETE /api/account/`

**Description:** Delete an account. User must have access to the account.

**Authentication:** Required

**Request Body:**
```json
{
    "account_id": "uuid"
}
```

**Response (200 OK):**
```json
{
    "message": "Account deleted successfully"
}
```

---

## Transaction Management

### Get Account Transactions

**Endpoint:** `GET /api/transactions/{account_id}/`

**Description:** Retrieve transaction history for a specific account. Returns both incoming and outgoing transactions.

**Authentication:** Required

**Path Parameters:**
- `account_id` (UUID): The ID of the account

**Response (200 OK):**
```json
[
    {
        "id": "uuid",
        "withdraw_account": "uuid",
        "credit_account": "uuid", 
        "amount": 0.00,
        "message": "string",
        "date": "YYYY-MM-DD"
    }
]
```

### Create Transaction

**Endpoint:** `POST /api/transaction/`

**Description:** Create a new transaction between accounts. Validates balance and account access.

**Authentication:** Required

**Request Body:**
```json
{
    "withdraw_account": "uuid",
    "credit_account": "uuid",
    "amount": 0.00,
    "message": "string"
}
```

**Response (201 Created):**
```json
{
    "id": "uuid",
    "withdraw_account": "uuid",
    "credit_account": "uuid",
    "amount": 0.00,
    "message": "string",
    "date": "YYYY-MM-DD"
}
```

### Get Transaction Details

**Endpoint:** `GET /api/transaction/{transaction_id}/`

**Description:** Retrieve details of a specific transaction. User must have access to at least one of the accounts involved.

**Authentication:** Required

**Path Parameters:**
- `transaction_id` (UUID): The ID of the transaction

**Response (200 OK):**
```json
{
    "id": "uuid",
    "withdraw_account": "uuid",
    "credit_account": "uuid",
    "amount": 0.00,
    "message": "string", 
    "date": "YYYY-MM-DD"
}
```

---

## Recurring Payments

### List Recurring Payments

**Endpoint:** `GET /api/recurring-payments/`

**Description:** Retrieve all recurring payments for the current user.

**Authentication:** Required

**Response (200 OK):**
```json
[
    {
        "id": "uuid",
        "withdraw_account": "uuid",
        "credit_account": "uuid",
        "amount": 0.00,
        "frequency": "MONTHLY",
        "status": "ACTIVE",
        "start_date": "YYYY-MM-DD",
        "end_date": "YYYY-MM-DD",  // Optional
        "next_payment_date": "YYYY-MM-DD",
        "payment_count": 0,
        "max_payments": 12,  // Optional
        "description": "string",
        "created_at": "YYYY-MM-DDTHH:MM:SSZ",
        "updated_at": "YYYY-MM-DDTHH:MM:SSZ"
    }
]
```

### Create Recurring Payment

**Endpoint:** `POST /api/recurring-payments/`

**Description:** Create a new recurring payment schedule.

**Authentication:** Required

**Request Body:**
```json
{
    "withdraw_account": "uuid",
    "credit_account": "uuid", 
    "amount": 0.00,
    "frequency": "MONTHLY",  // DAILY, WEEKLY, MONTHLY, YEARLY
    "start_date": "YYYY-MM-DD",
    "end_date": "YYYY-MM-DD",  // Optional
    "max_payments": 12,        // Optional
    "description": "string"
}
```

**Response (201 Created):**
```json
{
    "id": "uuid",
    "message": "Recurring payment created successfully",
    "recurring_payment": {
        "id": "uuid",
        "withdraw_account": "uuid",
        "credit_account": "uuid",
        "amount": 0.00,
        "frequency": "MONTHLY",
        "status": "ACTIVE",
        "start_date": "YYYY-MM-DD",
        "end_date": "YYYY-MM-DD",
        "next_payment_date": "YYYY-MM-DD",
        "payment_count": 0,
        "max_payments": 12,
        "description": "string",
        "created_at": "YYYY-MM-DDTHH:MM:SSZ",
        "updated_at": "YYYY-MM-DDTHH:MM:SSZ"
    }
}
```

### Get Recurring Payment Details

**Endpoint:** `GET /api/recurring-payments/{payment_id}/`

**Description:** Retrieve details of a specific recurring payment.

**Authentication:** Required

**Path Parameters:**
- `payment_id` (UUID): The ID of the recurring payment

**Response (200 OK):**
```json
{
    "id": "uuid",
    "withdraw_account": "uuid",
    "credit_account": "uuid",
    "amount": 0.00,
    "frequency": "MONTHLY",
    "status": "ACTIVE",
    "start_date": "YYYY-MM-DD",
    "end_date": "YYYY-MM-DD",
    "next_payment_date": "YYYY-MM-DD",
    "payment_count": 0,
    "max_payments": 12,
    "description": "string",
    "created_at": "YYYY-MM-DDTHH:MM:SSZ",
    "updated_at": "YYYY-MM-DDTHH:MM:SSZ"
}
```

### Update Recurring Payment

**Endpoint:** `PUT /api/recurring-payments/{payment_id}/`

**Description:** Update a recurring payment. Can modify amount, end date, max payments, and description.

**Authentication:** Required

**Path Parameters:**
- `payment_id` (UUID): The ID of the recurring payment

**Request Body:**
```json
{
    "amount": 0.00,           // Optional
    "end_date": "YYYY-MM-DD", // Optional
    "max_payments": 12,       // Optional
    "description": "string"   // Optional
}
```

**Response (200 OK):**
```json
{
    "message": "Recurring payment updated successfully",
    "recurring_payment": {
        "id": "uuid",
        "withdraw_account": "uuid",
        "credit_account": "uuid",
        "amount": 0.00,
        "frequency": "MONTHLY",
        "status": "ACTIVE",
        "start_date": "YYYY-MM-DD",
        "end_date": "YYYY-MM-DD",
        "next_payment_date": "YYYY-MM-DD",
        "payment_count": 0,
        "max_payments": 12,
        "description": "string",
        "created_at": "YYYY-MM-DDTHH:MM:SSZ",
        "updated_at": "YYYY-MM-DDTHH:MM:SSZ"
    }
}
```

### Pause Recurring Payment

**Endpoint:** `POST /api/recurring-payments/{payment_id}/`

**Description:** Pause an active recurring payment.

**Authentication:** Required

**Path Parameters:**
- `payment_id` (UUID): The ID of the recurring payment

**Request Body:**
```json
{
    "action": "pause"
}
```

**Response (200 OK):**
```json
{
    "message": "Recurring payment paused successfully"
}
```

### Resume Recurring Payment

**Endpoint:** `POST /api/recurring-payments/{payment_id}/`

**Description:** Resume a paused recurring payment.

**Authentication:** Required

**Path Parameters:**
- `payment_id` (UUID): The ID of the recurring payment

**Request Body:**
```json
{
    "action": "resume"
}
```

**Response (200 OK):**
```json
{
    "message": "Recurring payment resumed successfully"
}
```

### Cancel Recurring Payment

**Endpoint:** `POST /api/recurring-payments/{payment_id}/`

**Description:** Cancel a recurring payment permanently.

**Authentication:** Required

**Path Parameters:**
- `payment_id` (UUID): The ID of the recurring payment

**Request Body:**
```json
{
    "action": "cancel"
}
```

**Response (200 OK):**
```json
{
    "message": "Recurring payment cancelled successfully"
}
```

### Delete Recurring Payment

**Endpoint:** `DELETE /api/recurring-payments/{payment_id}/`

**Description:** Delete a recurring payment permanently.

**Authentication:** Required

**Path Parameters:**
- `payment_id` (UUID): The ID of the recurring payment

**Response (200 OK):**
```json
{
    "message": "Recurring payment deleted successfully"
}
```

---

## Error Handling

### HTTP Status Codes

- **200 OK** - Request successful
- **201 Created** - Resource created successfully
- **400 Bad Request** - Invalid request data
- **401 Unauthorized** - Missing or invalid authentication
- **403 Forbidden** - Access denied to resource
- **404 Not Found** - Resource not found
- **500 Internal Server Error** - Server error

### Error Response Format

All error responses follow this format:

```json
{
    "error": "Description of the error"
}
```

### Common Error Examples

**400 Bad Request:**
```json
{
    "error": "Missing required field: name"
}
```

**401 Unauthorized:**
```json
{
    "detail": "Given token not valid for any token type"
}
```

**403 Forbidden:**
```json
{
    "error": "You do not have access to this account"
}
```

**404 Not Found:**
```json
{
    "error": "Account not found"
}
```

---

## Response Formats

### Success Response Format

Successful responses typically include:
- **Data**: The requested resource(s)
- **Message**: Confirmation message (for creation/update operations)
- **HTTP Status Code**: Appropriate success code

### Date Format

All dates in API responses use ISO 8601 format:
- **Date only**: `YYYY-MM-DD`
- **DateTime**: `YYYY-MM-DDTHH:MM:SSZ`

### Monetary Values

All monetary amounts are represented as floating-point numbers with 2 decimal places precision. The system automatically rounds values using `math.ceil()` to prevent floating-point precision issues.

Example: `123.45`

---

## Data Models

### User Profile (Profile)
- `id` (UUID): Unique identifier
- `username` (string): Username for authentication
- `first_name` (string): User's first name
- `family_name` (string): User's family name
- `last_name` (string): User's last name
- `email` (string): User's email address
- `is_active` (boolean): Account status

### Account (Accounts)
- `id` (UUID): Unique identifier
- `name` (string): Human-readable account name
- `balance` (float): Current account balance
- `public_key` (string): Public key for blockchain integration

### Transaction (Transactions)
- `id` (UUID): Unique identifier
- `withdraw_account` (UUID): Source account ID
- `credit_account` (UUID): Destination account ID
- `amount` (float): Transaction amount
- `message` (string): Transaction description
- `date` (date): Transaction date

### Recurring Payment (RecurringPayment)
- `id` (UUID): Unique identifier
- `withdraw_account` (UUID): Source account ID
- `credit_account` (UUID): Destination account ID
- `amount` (float): Payment amount
- `frequency` (string): Payment frequency (DAILY, WEEKLY, MONTHLY, YEARLY)
- `status` (string): Payment status (ACTIVE, PAUSED, CANCELLED, COMPLETED)
- `start_date` (date): First payment date
- `end_date` (date): Optional last payment date
- `next_payment_date` (date): Next scheduled payment date
- `payment_count` (integer): Number of payments processed
- `max_payments` (integer): Optional maximum payment limit
- `description` (string): Payment description
- `created_at` (datetime): Creation timestamp
- `updated_at` (datetime): Last update timestamp

---

## Authentication Details

### JWT Token Structure

The API uses JSON Web Tokens (JWT) for authentication. Tokens contain:
- User ID
- Expiration time
- Token type (access/refresh)

### Token Lifetime

- **Access Token**: Short-lived (default: 15 minutes)
- **Refresh Token**: Long-lived (default: 7 days)

### Security Considerations

- Always use HTTPS in production
- Store tokens securely on the client side
- Implement proper token refresh logic
- Tokens are automatically invalidated on logout

---

## Rate Limiting

Currently, no rate limiting is implemented. Consider implementing rate limiting for production use to prevent abuse.

## CORS Configuration

The API is configured to accept requests from `http://localhost:4200` for development purposes. Update CORS settings for production domains.

---

## Example Usage

### Complete Authentication Flow

```javascript
// 1. Login
const loginResponse = await fetch('/api/token/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        username: 'user@example.com',
        password: 'password123'
    })
});
const tokens = await loginResponse.json();

// 2. Use access token for authenticated requests
const profileResponse = await fetch('/api/profile/', {
    headers: {
        'Authorization': `Bearer ${tokens.access}`,
        'Content-Type': 'application/json'
    }
});
const profile = await profileResponse.json();

// 3. Refresh token when needed
const refreshResponse = await fetch('/api/token/refresh/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        refresh: tokens.refresh
    })
});
const newTokens = await refreshResponse.json();
```

### Create Account and Transaction

```javascript
// Create account
const accountResponse = await fetch('/api/account/', {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        name: 'My Checking Account',
        balance: 1000.00
    })
});
const account = await accountResponse.json();

// Create transaction
const transactionResponse = await fetch('/api/transaction/', {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        withdraw_account: account.id,
        credit_account: 'recipient-account-id',
        amount: 100.00,
        message: 'Payment for services'
    })
});
const transaction = await transactionResponse.json();
```

---

## API Key Authentication & Management

PersifonPay supports API key authentication for secure external integrations. API keys are managed via the API (not the admin interface) and provide granular access control, rate limiting, and audit logging.

### Creating & Managing API Keys

- **Endpoint:** `POST /api/api-keys/`
- **Authentication:** JWT required (user must be logged in)
- **Request Body Example:**
```json
{
    "name": "My Integration Key",
    "description": "Key for external service",
    "permissions": "READ", // or "READ_WRITE", "ADMIN"
    "scopes": ["accounts:read", "transactions:read"],
    "allowed_ips": ["203.0.113.10"], // Optional
    "expires_at": "2025-12-31T23:59:59Z", // Optional
    "rate_limit": 1000 // Optional
}
```
- **Response Example (201 Created):**
```json
{
    "message": "API key created successfully",
    "api_key": {
        "id": "uuid",
        "name": "My Integration Key",
        "key": "<raw_api_key>" // Only shown once! Store securely.
    },
    "warning": "Save this API key securely. It will not be shown again."
}
```

- **List API Keys:** `GET /api/api-keys/`
- **Revoke API Key:** `DELETE /api/api-keys/{id}/`
- **Update API Key:** `PATCH /api/api-keys/{id}/`
- **View Usage Stats:** `GET /api/api-keys/{id}/usage/`

### Authenticating with an API Key

For endpoints that support API key authentication, include the following header:
```
Authorization: Api-Key <raw_api_key>
```

- The API key must be active, not expired or revoked.
- If IP restrictions are set, requests must originate from an allowed IP.
- Rate limits and scope restrictions apply.

### Example Request
```bash
curl -H "Authorization: Api-Key <raw_api_key>" \
     -H "Content-Type: application/json" \
     https://api.persifonpay.com/api/account/
```

### Security Best Practices
- Never share or expose your raw API key. Treat it like a password.
- Rotate API keys regularly and revoke unused keys.
- Use IP restrictions and scopes to limit access.
- Monitor usage and audit logs for suspicious activity.
- API keys are only visible once at creation—store them securely.

### Error Handling
- **401 Unauthorized:** Invalid, expired, or revoked API key.
- **403 Forbidden:** Insufficient permissions or scope.
- **429 Too Many Requests:** Rate limit exceeded.

### Notes
- API keys are for programmatic access only. Use JWT for user authentication.
- All API key actions are logged for security and compliance.
- Contact support if you lose your API key (it cannot be recovered, only regenerated).

---

*Last Updated: June 3, 2025*
*API Version: 1.0*
