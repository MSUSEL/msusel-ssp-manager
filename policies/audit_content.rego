package security.audit_content

import rego.v1

# AU-3: Content of Audit Records
# This policy validates that audit records include sufficient information to establish:
# - What type of event occurred
# - When the event occurred
# - Where the event occurred
# - The source of the event
# - The outcome of the event
# - The identity of any individuals or subjects associated with the event

# Check if audit record has all basic required fields
basic_content_valid if {
    # Required fields for all audit records
    required_fields := [
        "timestamp",      # When the event occurred
        "user_id",        # Identity of individuals/subjects
        "event_type",     # What type of event occurred
        "resource",       # Where the event occurred
        "outcome"         # Outcome of the event
    ]
    
    # Check if all required fields are present
    count([field | field = required_fields[_]; not input.audit_record[field]]) == 0
}

# Check if timestamp is in valid ISO 8601 format
timestamp_valid if {
    # Regex pattern for ISO 8601 format
    regex.match(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$`, input.audit_record.timestamp)
}

# Check if event type is valid
event_type_valid if {
    valid_event_types := [
        "login",
        "logout",
        "access_denied",
        "admin_action",
        "configuration_change",
        "data_access",
        "data_modification",
        "system_event",
        "security_event",
        "network_event"
    ]
    
    input.audit_record.event_type in valid_event_types
}

# Check if outcome is valid
outcome_valid if {
    valid_outcomes := [
        "success",
        "failure",
        "error",
        "unknown"
    ]
    
    input.audit_record.outcome in valid_outcomes
}

# Validate content for login events
login_content_valid if {
    input.audit_record.event_type == "login"
    
    # Additional required fields for login events
    required_fields := [
        "ip_address",     # Source of the event
        "auth_method"     # Authentication method used
    ]
    
    # Check if all required fields are present
    count([field | field = required_fields[_]; not input.audit_record[field]]) == 0
}

# Validate content for data access events
data_access_content_valid if {
    input.audit_record.event_type == "data_access"
    
    # Additional required fields for data access events
    required_fields := [
        "data_id"         # Identifier for the data being accessed
    ]
    
    # Check if all required fields are present
    count([field | field = required_fields[_]; not input.audit_record[field]]) == 0
}

# Validate content for configuration change events
config_change_content_valid if {
    input.audit_record.event_type == "configuration_change"
    
    # Additional required fields for configuration change events
    required_fields := [
        "old_value",      # Previous configuration value
        "new_value"       # New configuration value
    ]
    
    # Check if all required fields are present
    count([field | field = required_fields[_]; not input.audit_record[field]]) == 0
}

# Validate content for admin actions
admin_action_content_valid if {
    input.audit_record.event_type == "admin_action"
    
    # Admin actions should include details about the action
    input.audit_record["details"]
}

# Validate content for network events
network_event_content_valid if {
    input.audit_record.event_type == "network_event"
    
    # Network events should include source and destination information
    input.audit_record["source_ip"]
    input.audit_record["destination_ip"]
}

# Validate content for security events
security_event_content_valid if {
    input.audit_record.event_type == "security_event"
    
    # Security events should include severity and details
    input.audit_record["severity"]
    input.audit_record["details"]
}

# Check if event-specific content is valid
event_specific_content_valid if {
    input.audit_record.event_type == "login"
    login_content_valid
}

event_specific_content_valid if {
    input.audit_record.event_type == "data_access"
    data_access_content_valid
}

event_specific_content_valid if {
    input.audit_record.event_type == "configuration_change"
    config_change_content_valid
}

event_specific_content_valid if {
    input.audit_record.event_type == "admin_action"
    admin_action_content_valid
}

event_specific_content_valid if {
    input.audit_record.event_type == "network_event"
    network_event_content_valid
}

event_specific_content_valid if {
    input.audit_record.event_type == "security_event"
    security_event_content_valid
}

event_specific_content_valid if {
    # For events not requiring additional validation
    not input.audit_record.event_type in [
        "login", 
        "data_access", 
        "configuration_change", 
        "admin_action", 
        "network_event", 
        "security_event"
    ]
}

# Final decision on audit content validity
audit_content_valid if {
    basic_content_valid
    timestamp_valid
    event_type_valid
    outcome_valid
    event_specific_content_valid
}

# Generate detailed validation report
validation_report := {
    "basic_content": basic_content_valid,
    "timestamp": timestamp_valid,
    "event_type": event_type_valid,
    "outcome": outcome_valid,
    "event_specific_content": event_specific_content_valid,
    "overall_valid": audit_content_valid
}
