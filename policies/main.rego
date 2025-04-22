package security.main

import rego.v1
import data.security.access_control
import data.security.authentication
import data.security.audit
import data.security.session_crypto
import data.security.input_validation
import data.security.configuration_management

# Main decision point for all security controls
default allow := false

# Allow access if all applicable security controls pass
allow if {
    # Authentication controls (IA-2)
    authentication.allow
    
    # Access control (AC-2, AC-3)
    access_control.allow
    
    # Session management (SC-23)
    session_crypto.valid_session
    
    # Input validation (SI-3)
    input.request.data
    input_validation.input_valid
}

# For configuration changes, check additional controls
allow if {
    input.action == "configuration_change"
    
    # Authentication and access control
    authentication.allow
    access_control.allow
    
    # Configuration management controls (CM-2, CM-5)
    configuration_management.valid_change
}

# For file access, check integrity
allow if {
    input.action == "file_access"
    
    # Authentication and access control
    authentication.allow
    access_control.allow
    
    # File integrity (SI-7)
    input.file
    input_validation.file_integrity_valid
}

# Generate comprehensive audit record for all requests
audit_record := {
    "timestamp": input.request.time,
    "user_id": input.user.id,
    "action": input.action,
    "resource": input.resource,
    "outcome": allow,
    "client_ip": input.request.ip,
    "session_id": input.session.id,
    "request_details": input.request
}

# Flag suspicious activities
suspicious_activity if {
    # Failed authentication
    input.action == "authenticate"
    not authentication.allow
}

suspicious_activity if {
    # Access denied
    input.action == "access_resource"
    not access_control.allow
}

suspicious_activity if {
    # Input validation failure
    input.request.data
    not input_validation.input_valid
}

# Generate security incident for suspicious activities
security_incident if {
    suspicious_activity
    
    # Create incident record
    incident := {
        "timestamp": input.request.time,
        "type": "security_violation",
        "user_id": input.user.id,
        "client_ip": input.request.ip,
        "details": input.request,
        "severity": "medium"
    }
}
