# PersifonPay API Quick Start Guide

## Overview

This guide will help you get started with the PersifonPay API quickly. You'll learn how to authenticate, create accounts, and process payments.

## Prerequisites

- Python 3.12+
- Django 5.1.4
- Basic understanding of REST APIs
- HTTP client (curl, Postman, or similar)

## Base URL

```
http://localhost:8000
```

## Quick Setup

1. **Start the Django server:**
   ```bash
   python manage.py runserver
   ```

2. **Create a superuser (if needed):**
   ```bash
   python manage.py createsuperuser
   ```

## Authentication Flow

### 1. Obtain JWT Tokens

**Request:**
```bash
curl -X POST http://localhost:8000/api/token/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your_username",
    "password": "your_password"
  }'
```

**Response:**
```json
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

### 2. Use Access Token

Include the access token in the Authorization header for all authenticated requests:

```bash
Authorization: Bearer <your_access_token>
```

## Common API Workflows

### Workflow 1: User Profile and Account Setup

#### Step 1: Get User Profile
```bash
curl -X GET http://localhost:8000/api/profile/ \
  -H "Authorization: Bearer <your_access_token>"
```

#### Step 2: Create an Account
```bash
curl -X POST http://localhost:8000/api/account/ \
  -H "Authorization: Bearer <your_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Checking Account",
    "balance": 1000.00
  }'
```

**Response:**
```json
{
  "id": "account-uuid-here",
  "name": "My Checking Account",
  "balance": 1000.00
}
```

#### Step 3: List Your Accounts
```bash
curl -X GET http://localhost:8000/api/account/ \
  -H "Authorization: Bearer <your_access_token>"
```

### Workflow 2: Making a Transaction

#### Step 1: Create a Transaction
```bash
curl -X POST http://localhost:8000/api/transaction/ \
  -H "Authorization: Bearer <your_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "withdraw_account": "source-account-uuid",
    "credit_account": "destination-account-uuid",
    "amount": 100.00,
    "message": "Payment for services"
  }'
```

#### Step 2: View Transaction History
```bash
curl -X GET http://localhost:8000/api/transactions/<account_id>/ \
  -H "Authorization: Bearer <your_access_token>"
```

### Workflow 3: Setting Up Recurring Payments

#### Step 1: Create a Recurring Payment
```bash
curl -X POST http://localhost:8000/api/recurring-payments/ \
  -H "Authorization: Bearer <your_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "withdraw_account": "source-account-uuid",
    "credit_account": "destination-account-uuid",
    "amount": 50.00,
    "frequency": "MONTHLY",
    "start_date": "2025-06-03",
    "description": "Monthly subscription payment"
  }'
```

#### Step 2: List Recurring Payments
```bash
curl -X GET http://localhost:8000/api/recurring-payments/ \
  -H "Authorization: Bearer <your_access_token>"
```

#### Step 3: Pause a Recurring Payment
```bash
curl -X POST http://localhost:8000/api/recurring-payments/<payment_id>/ \
  -H "Authorization: Bearer <your_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "pause"
  }'
```

## JavaScript SDK Example

Here's a simple JavaScript wrapper for common operations:

```javascript
class PersifonPayAPI {
  constructor(baseURL = 'http://localhost:8000') {
    this.baseURL = baseURL;
    this.accessToken = null;
  }

  async login(username, password) {
    const response = await fetch(`${this.baseURL}/api/token/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    
    if (response.ok) {
      const tokens = await response.json();
      this.accessToken = tokens.access;
      return tokens;
    }
    throw new Error('Login failed');
  }

  async getProfile() {
    return this.request('GET', '/api/profile/');
  }

  async createAccount(name, balance = 0) {
    return this.request('POST', '/api/account/', { name, balance });
  }

  async createTransaction(withdrawAccount, creditAccount, amount, message) {
    return this.request('POST', '/api/transaction/', {
      withdraw_account: withdrawAccount,
      credit_account: creditAccount,
      amount,
      message
    });
  }

  async createRecurringPayment(withdrawAccount, creditAccount, amount, frequency, startDate, description) {
    return this.request('POST', '/api/recurring-payments/', {
      withdraw_account: withdrawAccount,
      credit_account: creditAccount,
      amount,
      frequency,
      start_date: startDate,
      description
    });
  }

  async request(method, endpoint, data = null) {
    const options = {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.accessToken}`
      }
    };

    if (data) {
      options.body = JSON.stringify(data);
    }

    const response = await fetch(`${this.baseURL}${endpoint}`, options);
    
    if (response.ok) {
      return await response.json();
    }
    
    const error = await response.json();
    throw new Error(error.error || 'Request failed');
  }
}

// Usage example
const api = new PersifonPayAPI();

async function demo() {
  try {
    // Login
    await api.login('username', 'password');
    
    // Get profile
    const profile = await api.getProfile();
    console.log('Profile:', profile);
    
    // Create account
    const account = await api.createAccount('Demo Account', 1000);
    console.log('Created account:', account);
    
  } catch (error) {
    console.error('Error:', error.message);
  }
}
```

## Python SDK Example

```python
import requests
import json

class PersifonPayAPI:
    def __init__(self, base_url='http://localhost:8000'):
        self.base_url = base_url
        self.access_token = None
    
    def login(self, username, password):
        """Authenticate and get access token"""
        response = requests.post(f'{self.base_url}/api/token/', json={
            'username': username,
            'password': password
        })
        
        if response.status_code == 200:
            tokens = response.json()
            self.access_token = tokens['access']
            return tokens
        else:
            raise Exception(f'Login failed: {response.text}')
    
    def _request(self, method, endpoint, data=None):
        """Make authenticated request"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        url = f'{self.base_url}{endpoint}'
        
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers)
        elif method.upper() == 'POST':
            response = requests.post(url, headers=headers, json=data)
        elif method.upper() == 'PUT':
            response = requests.put(url, headers=headers, json=data)
        elif method.upper() == 'DELETE':
            response = requests.delete(url, headers=headers, json=data)
        
        if response.status_code in [200, 201]:
            return response.json()
        else:
            raise Exception(f'Request failed: {response.text}')
    
    def get_profile(self):
        """Get user profile"""
        return self._request('GET', '/api/profile/')
    
    def create_account(self, name, balance=0):
        """Create a new account"""
        return self._request('POST', '/api/account/', {
            'name': name,
            'balance': balance
        })
    
    def create_transaction(self, withdraw_account, credit_account, amount, message):
        """Create a new transaction"""
        return self._request('POST', '/api/transaction/', {
            'withdraw_account': withdraw_account,
            'credit_account': credit_account,
            'amount': amount,
            'message': message
        })
    
    def create_recurring_payment(self, withdraw_account, credit_account, amount, 
                               frequency, start_date, description, end_date=None, max_payments=None):
        """Create a recurring payment"""
        data = {
            'withdraw_account': withdraw_account,
            'credit_account': credit_account,
            'amount': amount,
            'frequency': frequency,
            'start_date': start_date,
            'description': description
        }
        
        if end_date:
            data['end_date'] = end_date
        if max_payments:
            data['max_payments'] = max_payments
            
        return self._request('POST', '/api/recurring-payments/', data)

# Usage example
if __name__ == '__main__':
    api = PersifonPayAPI()
    
    try:
        # Login
        tokens = api.login('username', 'password')
        print('Logged in successfully')
        
        # Get profile
        profile = api.get_profile()
        print(f'User profile: {profile}')
        
        # Create account
        account = api.create_account('Demo Account', 1000.00)
        print(f'Created account: {account}')
        
    except Exception as e:
        print(f'Error: {e}')
```

## Error Handling

### Common HTTP Status Codes

- **200 OK** - Request successful
- **201 Created** - Resource created successfully
- **400 Bad Request** - Invalid request data
- **401 Unauthorized** - Missing or invalid authentication
- **403 Forbidden** - Access denied to resource
- **404 Not Found** - Resource not found
- **500 Internal Server Error** - Server error

### Error Response Format

```json
{
  "error": "Description of the error"
}
```

### Common Errors and Solutions

1. **"Given token not valid for any token type"**
   - Solution: Refresh your access token or login again

2. **"You do not have access to this account"**
   - Solution: Ensure you're using an account that belongs to your user

3. **"Insufficient balance"**
   - Solution: Check account balance before making transactions

4. **"Missing required field: name"**
   - Solution: Include all required fields in your request

## Rate Limiting

Currently no rate limiting is implemented, but consider implementing it for production use.

## Security Best Practices

1. **Use HTTPS in production**
2. **Store tokens securely**
3. **Implement token refresh logic**
4. **Validate all input data**
5. **Use environment variables for sensitive data**

## Testing

### Running Tests
```bash
python manage.py test
```

### Manual Testing with curl

Create a simple test script:

```bash
#!/bin/bash

# Login and get token
TOKEN=$(curl -s -X POST http://localhost:8000/api/token/ \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}' | \
  python -c "import sys, json; print(json.load(sys.stdin)['access'])")

# Create account
ACCOUNT=$(curl -s -X POST http://localhost:8000/api/account/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test Account","balance":1000}')

echo "Created account: $ACCOUNT"
```

## Advanced Features

### Recurring Payment Processing

Process recurring payments using the management command:

```bash
# Dry run (preview what would be processed)
python manage.py process_recurring_payments --dry-run

# Actually process payments
python manage.py process_recurring_payments
```

### Database Transactions

All financial operations use atomic database transactions to ensure data consistency:

```python
from django.db import transaction

with transaction.atomic():
    # All database operations here are atomic
    pass
```

## Support and Documentation

- **Full API Documentation**: [API_DOCUMENTATION.md](./API_DOCUMENTATION.md)
- **OpenAPI Specification**: [openapi.yaml](./openapi.yaml)
- **Interactive Docs**: Open [docs/api-docs.html](./docs/api-docs.html) in your browser
- **Postman Collection**: Import [docs/PersifonPay-API.postman_collection.json](./docs/PersifonPay-API.postman_collection.json)

## Next Steps

1. Explore the interactive API documentation
2. Import the Postman collection for easy testing
3. Review the full API documentation for detailed endpoint information
4. Check out the demo scripts in the project root
5. Implement your own payment processing logic

---

*Happy coding with PersifonPay API! 🚀*
