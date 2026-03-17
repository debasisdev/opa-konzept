# OPA Authorization Concept

A comprehensive Open Policy Agent (OPA) setup for API Gateway authorization with RBAC, ABAC, and tenant isolation policies.

## Overview

When a user requests the battery status endpoint, your API Gateway (like Kong or AWS API Gateway) pauses the request, decodes the user's Role JWT, and sends a JSON payload to OPA.

The policy evaluates the request against multiple authorization criteria:
- **RBAC** (Role-Based Access Control): Validates user roles
- **ABAC** (Attribute-Based Access Control): Checks user attributes like data clearance and region
- **Tenant Isolation**: Ensures users can only access their tenant's resources
- **Use-Case Constraints**: Validates the request's intended use case

### Request Payload Example

```json
{
  "input": {
    "request": {
      "method": "GET",
      "matched_route": "/api/v1/brands/{brand}/vehicles/*/battery-status",
      "path_params": {
        "brand": "porsche",
        "vin": "WP0123456789"
      },
      "headers": {
        "X-VWG-Use-Case": "predictive_maintenance"
      }
    },
    "token": {
      "tenant_id": "porsche",
      "roles": ["Global_Diagnostic_Tech", "Standard_Employee"],
      "data_clearance": "confidential",
      "region": "EU"
    }
  }
}
```

## Usage

### Running Policy Evaluation

```bash
opa eval -i input/input.json -d authz.rego -d rules.json "data.vwg.authz.allow"
```

### Running Tests

```bash
opa test -v .
```

## Project Structure

```
├── authz.rego                 # Main authorization policy
├── authz_test.rego           # Policy tests
├── input/
│   ├── input.json            # Sample request payload
│   └── gw.json               # Policy rules and configuration
├── rules/
│   └── rules.json            # Generated policy rules
└── README.md
```

## Requirements

- [OPA (Open Policy Agent)](https://www.openpolicyagent.org/) - v0.45.0 or higher
- Python 3.8+ (for translator.py)
