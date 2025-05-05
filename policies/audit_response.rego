package security.audit_response

import rego.v1

# AU-5: Response to Audit Processing Failures
# This policy validates that the system:
# a. Alerts designated personnel in the event of an audit processing failure
# b. Takes appropriate actions in response to audit failures
# c. Shuts down, overrides, or takes other actions to protect audit capability

# Check if audit failure alerts are properly configured
audit_alerts_configured if {
    # Verify that alerts are enabled
    input.audit_response.alerts_enabled == true
    
    # Verify that alert recipients are configured
    count(input.audit_response.alert_recipients) > 0
}

# Check if audit failure actions are properly configured
audit_actions_configured if {
    # Verify that automatic actions are enabled
    input.audit_response.actions_enabled == true
    
    # Verify that at least one action is configured
    count(input.audit_response.actions) > 0
}

# Check if system shutdown on audit failure is properly configured
system_shutdown_configured if {
    # Verify that system shutdown is configured for critical failures
    some action in input.audit_response.actions
    action.type == "shutdown"
    action.trigger == "critical_failure"
}

# Check if audit capacity protection is properly configured
audit_capacity_protection_configured if {
    # Verify that capacity protection is enabled
    input.audit_response.capacity_protection_enabled == true
    
    # Verify that capacity threshold is set appropriately
    input.audit_response.capacity_threshold_percent <= 90
}

# Check if real-time monitoring is properly configured
real_time_monitoring_configured if {
    # Verify that real-time monitoring is enabled
    input.audit_response.real_time_monitoring_enabled == true
    
    # Verify that monitoring interval is appropriate
    input.audit_response.monitoring_interval_seconds <= 300
}

# Check if audit failure notification is properly configured
notification_configured if {
    # Verify that notification is enabled
    input.audit_response.notification_enabled == true
    
    # Verify that notification methods are configured
    count(input.audit_response.notification_methods) > 0
}

# Check if audit failure is properly handled
audit_failure_handled if {
    # Verify that the system handled the audit failure correctly
    input.audit_response.failure_handled == true
    
    # Verify that appropriate actions were taken
    count(input.audit_response.actions_taken) > 0
}

# Final decision on audit response compliance
audit_response_compliant if {
    audit_alerts_configured
    audit_actions_configured
    system_shutdown_configured
    audit_capacity_protection_configured
    real_time_monitoring_configured
    notification_configured
}

# Generate detailed compliance report
compliance_report := {
    "audit_alerts_configured": audit_alerts_configured,
    "audit_actions_configured": audit_actions_configured,
    "system_shutdown_configured": system_shutdown_configured,
    "audit_capacity_protection_configured": audit_capacity_protection_configured,
    "real_time_monitoring_configured": real_time_monitoring_configured,
    "notification_configured": notification_configured,
    "audit_failure_handled": audit_failure_handled,
    "overall_compliant": audit_response_compliant
}
