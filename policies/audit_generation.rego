package security.audit_generation

import rego.v1

# AU-12: Audit Generation
# This policy validates that the system:
# a. Provides audit record generation capability for the events defined in AU-2
# b. Allows designated organizational personnel to select which events are to be audited
# c. Generates audit records for the events defined in AU-2 with the content defined in AU-3

# Check if audit generation is enabled at the system level
system_audit_enabled if {
    # Verify that system-level audit is enabled
    input.audit_generation.system_level.enabled == true
    
    # Verify that system-level audit components are configured
    count(input.audit_generation.system_level.components) > 0
}

# Check if audit generation is enabled at the component level
component_audit_enabled if {
    # Verify that component-level audit is enabled
    input.audit_generation.component_level.enabled == true
    
    # Verify that component-level audit components are configured
    count(input.audit_generation.component_level.components) > 0
}

# Check if audit generation is configured for required events
required_events_configured if {
    # Define required events that must be audited
    required_events := [
        "login",
        "logout",
        "configuration_change",
        "data_access",
        "data_modification",
        "security_event",
        "admin_action"
    ]
    
    # Verify that all required events are configured for auditing
    missing_events := [event | event = required_events[_]; not event in input.audit_generation.events]
    count(missing_events) == 0
}

# Check if audit generation allows selection of events
event_selection_enabled if {
    # Verify that event selection is enabled
    input.audit_generation.event_selection.enabled == true
    
    # Verify that authorized roles for event selection are configured
    count(input.audit_generation.event_selection.authorized_roles) > 0
}

# Check if audit generation produces records with required content
audit_content_compliant if {
    # Define required fields for audit records
    required_fields := [
        "timestamp",
        "user_id",
        "event_type",
        "resource",
        "outcome",
        "system_component"
    ]
    
    # Verify that all required fields are included in audit records
    missing_fields := [field | field = required_fields[_]; not field in input.audit_generation.record_fields]
    count(missing_fields) == 0
}

# Check if audit generation testing is configured
audit_testing_configured if {
    # Verify that audit testing is enabled
    input.audit_generation.testing.enabled == true
    
    # Verify that audit testing frequency is configured
    input.audit_generation.testing.frequency_days > 0
    
    # Verify that last test date is recorded
    input.audit_generation.testing.last_test_date
    
    # Verify that test results are recorded
    input.audit_generation.testing.last_test_result
}

# Check if a specific event is configured for auditing
event_configured_for_audit if {
    # Check if the event is in the list of events to audit
    input.event.type in input.audit_generation.events
}

# Check if a specific component is configured for auditing
component_configured_for_audit if {
    # Check if the component is in the list of components to audit
    input.component.id in [comp.id | comp = input.audit_generation.component_level.components[_]]
}

# Final decision on audit generation compliance
audit_generation_compliant if {
    system_audit_enabled
    component_audit_enabled
    required_events_configured
    event_selection_enabled
    audit_content_compliant
    audit_testing_configured
}
