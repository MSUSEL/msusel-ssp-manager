package security.audit_retention

import rego.v1

# AU-11: Audit Record Retention
# This policy validates that the system:
# a. Retains audit records for a specified time period to provide support for after-the-fact 
#    investigations of security incidents
# b. Ensures that the retention period is consistent with records retention policies and 
#    regulatory requirements

# Check if retention period is properly configured
retention_period_configured if {
    # Verify that retention policy is enabled
    input.audit_retention.retention_policy.enabled == true
    
    # Verify that retention period is specified and meets minimum requirements
    input.audit_retention.retention_policy.retention_period_days > 0
    
    # Verify that retention period meets organizational requirements
    input.audit_retention.retention_policy.retention_period_days >= input.audit_retention.retention_policy.required_minimum_days
}

# Check if archival mechanisms are properly configured
archival_mechanisms_configured if {
    # Verify that archival is enabled
    input.audit_retention.archival.enabled == true
    
    # Verify that archival method is specified
    input.audit_retention.archival.method in ["offline_storage", "cloud_storage", "tape_backup", "disk_backup"]
    
    # Verify that archival schedule is configured
    input.audit_retention.archival.schedule.frequency in ["daily", "weekly", "monthly"]
    
    # Verify that archival location is specified
    input.audit_retention.archival.location
}

# Check if retrieval capabilities are properly configured
retrieval_capabilities_configured if {
    # Verify that retrieval is enabled
    input.audit_retention.retrieval.enabled == true
    
    # Verify that retrieval methods are specified
    count(input.audit_retention.retrieval.methods) > 0
    
    # Verify that retrieval authorization is configured
    count(input.audit_retention.retrieval.authorized_roles) > 0
    
    # Verify that retrieval process is documented
    input.audit_retention.retrieval.process_documented == true
}

# Check if retention policy complies with organizational requirements
retention_policy_compliant if {
    # Verify that retention policy is compliant with organizational policy
    input.audit_retention.compliance.organizational_policy_compliant == true
    
    # Verify that retention policy is compliant with regulatory requirements
    input.audit_retention.compliance.regulatory_requirements_compliant == true
    
    # Verify that compliance is reviewed periodically
    input.audit_retention.compliance.last_review_date
    
    # Verify that the last review was within the required timeframe (e.g., last 365 days)
    time.parse_rfc3339_ns(input.audit_retention.compliance.last_review_date) > time.parse_rfc3339_ns(input.audit_retention.compliance.review_cutoff_date)
}

# Check if secure storage of archived audit records is configured
secure_archive_storage_configured if {
    # Verify that secure storage is enabled
    input.audit_retention.secure_storage.enabled == true
    
    # Verify that encryption is enabled for archived records
    input.audit_retention.secure_storage.encryption_enabled == true
    
    # Verify that access controls are in place for archived records
    count(input.audit_retention.secure_storage.access_controls) > 0
    
    # Verify that integrity verification is configured
    input.audit_retention.secure_storage.integrity_verification_enabled == true
}

# Validate a specific retention configuration
retention_configuration_valid if {
    # Check if retention period is valid
    input.retention_config.retention_period_days > 0
    
    # Check if retention period meets minimum requirements
    input.retention_config.retention_period_days >= input.retention_config.required_minimum_days
    
    # Check if archival method is valid
    input.retention_config.archival_method in ["offline_storage", "cloud_storage", "tape_backup", "disk_backup"]
}

# Final decision on audit retention compliance
audit_retention_compliant if {
    retention_period_configured
    archival_mechanisms_configured
    retrieval_capabilities_configured
    retention_policy_compliant
    secure_archive_storage_configured
}
