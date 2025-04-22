# UGov Services Security Controls

This directory contains Open Policy Agent (OPA) policies and Chef InSpec tests for the security controls specified in the System Security Plan (SSP) for UGov Services.

## Overview

The OPA policies and InSpec tests in this repository are designed to validate the security controls implemented in the UGov Services application without requiring the actual implementation of those controls. This allows for policy-as-code testing and validation of security requirements.

## Directory Structure

```
policies/
├── opa/                  # OPA policy files
│   ├── access_control.rego   # AC-2, AC-3 controls
│   ├── authentication.rego   # IA-2 controls
│   ├── audit.rego            # AU-2, AU-3, AU-6 controls
│   ├── session_crypto.rego   # SC-23, SC-12, SC-13 controls
│   ├── input_validation.rego # SI-3, SI-7 controls
│   ├── configuration_management.rego # CM-2, CM-5, CM-8 controls
│   ├── main.rego             # Main policy file
│   └── data.json             # Sample data for OPA
├── inspec/                # InSpec test files
│   ├── access_control_test.rb
│   ├── authentication_test.rb
│   ├── audit_test.rb
│   ├── session_crypto_test.rb
│   ├── input_validation_test.rb
│   ├── configuration_management_test.rb
│   └── inspec.yml             # InSpec profile metadata
└── README.md              # This file
```

## Security Controls Implemented

The OPA policies and InSpec tests cover the following security controls from the SSP:

1. **Access Control (AC)**
   - AC-2: Account Management
   - AC-3: Access Enforcement

2. **Identification and Authentication (IA)**
   - IA-2: Identification and Authentication

3. **Audit and Accountability (AU)**
   - AU-2: Audit Events
   - AU-3: Content of Audit Records
   - AU-6: Audit Review, Analysis, and Reporting
   - AU-8: Time Stamps
   - AU-9: Protection of Audit Information
   - AU-10: Non-repudiation
   - AU-11: Audit Record Retention
   - AU-12: Audit Generation

4. **System and Communications Protection (SC)**
   - SC-5: Denial of Service Protection
   - SC-7: Boundary Protection
   - SC-12: Cryptographic Key Establishment and Management
   - SC-13: Cryptographic Protection
   - SC-16: Transmission of Security Attributes
   - SC-23: Session Authenticity
   - SC-28: Protection of Information at Rest

5. **System and Information Integrity (SI)**
   - SI-2: Flaw Remediation
   - SI-3: Malicious Code Protection
   - SI-4: Information System Monitoring
   - SI-7: Software, Firmware, and Information Integrity

6. **Configuration Management (CM)**
   - CM-2: Baseline Configuration
   - CM-5: Access Restrictions for Change
   - CM-8: Information System Component Inventory

## Using OPA Policies

### Prerequisites

- OPA CLI installed (https://www.openpolicyagent.org/docs/latest/#1-download-opa)

### Running OPA Policies

1. Start OPA server with the policies:

```bash
opa run --server policies/opa/
```

2. Test a policy decision:

```bash
curl -X POST http://localhost:8181/v1/data/security/main/allow -d @input.json -H 'Content-Type: application/json'
```

Where `input.json` contains the input data for the policy decision.

## Using InSpec Tests

### Prerequisites

- Chef InSpec installed (https://docs.chef.io/inspec/install/)
- UGov Services application running (or mocked)

### Running InSpec Tests

1. Run all tests:

```bash
inspec exec policies/inspec
```

2. Run a specific test:

```bash
inspec exec policies/inspec/access_control_test.rb
```

## Integration with UGov Services

In a real environment, the UGov Services application would:

1. Send requests to the OPA server for policy decisions
2. Receive the decision (allow/deny)
3. Enforce the decision
4. Log the interaction

The InSpec tests validate that this flow works correctly by:

1. Making requests to the UGov Services application
2. Verifying that the application correctly enforces the OPA policy decisions
3. Checking that appropriate logs are generated

## Mock Testing

For testing without a real implementation, you can use the provided mock server:

```bash
# Start the mock server
cd mock
npm install
npm start
```

The mock server simulates the UGov Services application and its interaction with OPA, allowing the InSpec tests to run without a real implementation.

## License

This project is licensed under the Apache License 2.0.
