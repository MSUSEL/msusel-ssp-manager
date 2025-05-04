package security.audit_storage

import rego.v1

# AU-4: Audit Storage Capacity
# This policy validates that the system allocates sufficient audit record storage capacity
# and configures auditing to reduce the likelihood of such capacity being exceeded.

# Check if audit storage capacity is sufficient
storage_capacity_sufficient if {
    # Verify that allocated storage meets minimum requirements
    input.audit_storage.capacity_gb >= input.audit_storage.required_capacity_gb
}

# Check if storage monitoring is properly configured
storage_monitoring_configured if {
    # Verify that storage monitoring is enabled
    input.audit_storage.monitoring_enabled == true
    
    # Verify monitoring interval is appropriate (in minutes)
    input.audit_storage.monitoring_interval_minutes <= 60
}

# Check if storage alerts are properly configured
storage_alerts_configured if {
    # Verify that alerts are enabled
    input.audit_storage.alerts_enabled == true
    
    # Verify that warning threshold is set appropriately (percentage)
    input.audit_storage.warning_threshold_percent <= 80
    
    # Verify that critical threshold is set appropriately (percentage)
    input.audit_storage.critical_threshold_percent <= 90
    
    # Verify that alert recipients are configured
    count(input.audit_storage.alert_recipients) > 0
}

# Check if retention policy is properly configured
retention_policy_configured if {
    # Verify that retention policy is enabled
    input.audit_storage.retention_policy_enabled == true
    
    # Verify that minimum retention period meets requirements (in days)
    input.audit_storage.retention_period_days >= 180
    
    # Verify that archiving is configured for older records
    input.audit_storage.archiving_enabled == true
}

# Check if current storage usage is within acceptable limits
storage_usage_acceptable if {
    # Calculate current usage percentage
    usage_percent := (input.audit_storage.used_gb / input.audit_storage.capacity_gb) * 100
    
    # Verify that usage is below critical threshold
    usage_percent < input.audit_storage.critical_threshold_percent
}

# Check if storage is approaching capacity (warning level)
storage_approaching_capacity if {
    # Calculate current usage percentage
    usage_percent := (input.audit_storage.used_gb / input.audit_storage.capacity_gb) * 100
    
    # Check if usage is between warning and critical thresholds
    usage_percent >= input.audit_storage.warning_threshold_percent
    usage_percent < input.audit_storage.critical_threshold_percent
}

# Check if storage is at critical capacity
storage_at_critical_capacity if {
    # Calculate current usage percentage
    usage_percent := (input.audit_storage.used_gb / input.audit_storage.capacity_gb) * 100
    
    # Check if usage is at or above critical threshold
    usage_percent >= input.audit_storage.critical_threshold_percent
}

# Check if automatic actions are configured for capacity management
automatic_actions_configured if {
    # Verify that automatic actions are enabled
    input.audit_storage.automatic_actions_enabled == true
    
    # Verify that at least one action is configured
    count(input.audit_storage.automatic_actions) > 0
}

# Final decision on audit storage compliance
audit_storage_compliant if {
    storage_capacity_sufficient
    storage_monitoring_configured
    storage_alerts_configured
    retention_policy_configured
    not storage_at_critical_capacity
    automatic_actions_configured
}

# Generate detailed compliance report
compliance_report := {
    "storage_capacity_sufficient": storage_capacity_sufficient,
    "storage_monitoring_configured": storage_monitoring_configured,
    "storage_alerts_configured": storage_alerts_configured,
    "retention_policy_configured": retention_policy_configured,
    "storage_usage_acceptable": storage_usage_acceptable,
    "storage_approaching_capacity": storage_approaching_capacity,
    "storage_at_critical_capacity": storage_at_critical_capacity,
    "automatic_actions_configured": automatic_actions_configured,
    "overall_compliant": audit_storage_compliant
}
