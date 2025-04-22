package security.audit

import rego.v1

# AU-2: Audit Events
# AU-3: Content of Audit Records
# AU-6: Audit Review, Analysis, and Reporting

# Check if an event should be audited
should_audit if {
    # List of events that should always be audited
    critical_events := [
        "login",
        "logout",
        "access_denied",
        "admin_action",
        "configuration_change",
        "data_access",
        "data_modification"
    ]
    
    # Check if the current event is in the critical events list
    input.event.type in critical_events
}

# Check if audit record has all required fields
audit_record_valid if {
    # Required fields for all audit records
    required_fields := [
        "timestamp",
        "user_id",
        "event_type",
        "resource",
        "outcome"
    ]
    
    # Check if all required fields are present
    count([field | field = required_fields[_]; not input.audit_record[field]]) == 0
}

# Additional fields required for specific event types
additional_fields_valid if {
    # For login events, require IP address and authentication method
    input.event.type == "login"
    input.audit_record["ip_address"]
    input.audit_record["auth_method"]
}

additional_fields_valid if {
    # For data access events, require data identifier
    input.event.type == "data_access"
    input.audit_record["data_id"]
}

additional_fields_valid if {
    # For configuration changes, require old and new values
    input.event.type == "configuration_change"
    input.audit_record["old_value"]
    input.audit_record["new_value"]
}

additional_fields_valid if {
    # For events not requiring additional fields
    not input.event.type in ["login", "data_access", "configuration_change"]
}

# Determine if an audit record should be flagged for review
flag_for_review if {
    # Flag failed login attempts
    input.event.type == "login"
    input.audit_record.outcome == "failure"
}

flag_for_review if {
    # Flag access denied events
    input.event.type == "access_denied"
}

flag_for_review if {
    # Flag admin actions
    input.event.type == "admin_action"
}

flag_for_review if {
    # Flag suspicious IP addresses
    input.audit_record["ip_address"]
    input.audit_record.ip_address in data.suspicious_ips
}

# Final audit decision
valid_audit if {
    should_audit
    audit_record_valid
    additional_fields_valid
}
