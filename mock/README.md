# UGov Services Mock Server

This is a mock server that simulates the UGov Services application for testing OPA policies and InSpec tests.

## Overview

The mock server provides endpoints that simulate the behavior of the UGov Services application, including:

- Authentication and authorization
- Access control
- Input validation
- Configuration management
- Audit logging

## Prerequisites

- Node.js (v14 or higher)
- npm

## Installation

```bash
npm install
```

## Usage

```bash
npm start
```

The server will start on port 8000.

## Endpoints

### Authentication

- `POST /login`: Authenticate a user
  - Request body: `{ "username": "string", "password": "string", "mfa_code": "string", "type": "string", "factors": number }`
  - Response: `{ "authenticated": boolean, "access_token": "string" }`

### Access Control

- `GET /user_profile`: Access user profile (requires authentication)
  - Headers: `Authorization: Bearer <token>`
  - Response: `{ "allowed": boolean, "profile": object }`

- `GET /admin_panel`: Access admin panel (requires admin role)
  - Headers: `Authorization: Bearer <token>`
  - Response: `{ "allowed": boolean, "admin_panel": object }`

### Input Validation

- `POST /submit_data`: Submit data for validation
  - Request body: `{ "field_type": "string", "data": "string" }`
  - Response: `{ "valid": boolean, "reason": "string" }`

- `POST /validate_file`: Validate file integrity
  - Request body: `{ "file": { "name": "string", "hash": "string" } }`
  - Response: `{ "valid": boolean, "reason": "string" }`

### Configuration Management

- `POST /config_change`: Make a configuration change (requires admin role)
  - Headers: `Authorization: Bearer <token>`
  - Request body: `{ "change": { "ticket_id": "string", "approved_by": "string", "component": "string", "setting": "string", "value": any } }`
  - Response: `{ "allowed": boolean, "change_id": "string" }`

- `POST /check_compliance`: Check if a component is compliant with baseline
  - Request body: `{ "component": { "id": "string", "type": "string", "settings": object } }`
  - Response: `{ "compliant": boolean, "non_compliant_settings": array }`

- `POST /check_inventory`: Check if a component is in the inventory
  - Request body: `{ "component": { "id": "string" } }`
  - Response: `{ "in_inventory": boolean }`

- `POST /check_dependencies`: Check if dependencies are approved
  - Request body: `{ "component": { "id": "string", "dependencies": array } }`
  - Response: `{ "approved": boolean, "unapproved_dependencies": array }`

### System Information

- `GET /tls_info`: Get TLS information
  - Response: `{ "tls_version": "string", "cipher_suite": "string" }`

- `GET /storage_info`: Get storage encryption information
  - Response: `{ "encryption_algorithm": "string", "key_management": "string" }`

## Logs

The mock server generates two log files:

- `logs/opa_interactions.log`: Logs interactions with OPA policies
- `logs/audit.log`: Logs audit events

These logs are used by the InSpec tests to verify that the correct audit records are generated.

## License

This project is licensed under the Apache License 2.0.
