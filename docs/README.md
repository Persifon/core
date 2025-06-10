# PersifonPay API Documentation

This directory contains comprehensive documentation for the PersifonPay API.

## Documentation Files

### 📖 Core Documentation
- **[API_DOCUMENTATION.md](../API_DOCUMENTATION.md)** - Complete API reference with all endpoints, request/response formats, and examples
- **[QUICK_START.md](../QUICK_START.md)** - Quick start guide to get up and running with the API
- **[TASKS_PROGRESS.md](../TASKS_PROGRESS.md)** - Project status, completed features, and roadmap

### 🔧 Technical Specifications
- **[openapi.yaml](../openapi.yaml)** - OpenAPI 3.0 specification for automatic documentation generation
- **[api-docs.html](./api-docs.html)** - Interactive Swagger UI documentation (open in browser)

### 🧪 Testing Resources  
- **[PersifonPay-API.postman_collection.json](./PersifonPay-API.postman_collection.json)** - Complete Postman collection for API testing

## How to Use

### 1. Interactive Documentation
Open `api-docs.html` in your web browser to explore the API interactively:
```bash
open docs/api-docs.html
```

This provides:
- Interactive API testing
- Request/response examples
- Schema validation
- Authentication testing

### 2. Postman Testing
Import the Postman collection for comprehensive API testing:

1. Open Postman
2. Click "Import"
3. Select `PersifonPay-API.postman_collection.json`
4. Configure variables (base_url, credentials)
5. Start testing!

### 3. Development Reference
Use the markdown documentation files for:
- Implementation guidance
- API reference while coding
- Understanding data models
- Error handling patterns

## Quick Links

| Resource | Purpose | Best For |
|----------|---------|----------|
| [Quick Start](../QUICK_START.md) | Get started fast | New developers |
| [API Docs](../API_DOCUMENTATION.md) | Complete reference | Implementation |
| [Interactive Docs](./api-docs.html) | Live testing | API exploration |
| [Postman Collection](./PersifonPay-API.postman_collection.json) | Testing suite | QA and testing |
| [OpenAPI Spec](../openapi.yaml) | Machine-readable spec | Tool integration |

## Features Covered

✅ **Authentication & Authorization**
- JWT token management
- User authentication flow
- Permission-based access control

✅ **Account Management**
- Create and manage user accounts
- Balance tracking and updates
- Account access validation

✅ **Transaction Processing**
- Account-to-account transfers
- Transaction history and tracking
- Balance validation and atomic operations

✅ **Recurring Payments**
- Flexible scheduling (daily, weekly, monthly, yearly)
- Payment status management
- Automatic processing capabilities

✅ **User Profile Management**
- Profile information updates
- Account association management

## Getting Started

1. **Read the Quick Start Guide** - Get familiar with basic concepts
2. **Try the Interactive Docs** - Explore endpoints hands-on
3. **Import Postman Collection** - Set up your testing environment
4. **Reference the API Docs** - Implement your integration

## Support

For questions or issues:
1. Check the documentation first
2. Review error handling patterns
3. Examine the demo scripts in the project root
4. Refer to the task progress for known limitations

---

*Last Updated: June 3, 2025*
