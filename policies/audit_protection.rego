package security.audit_protection

import rego.v1

# AU-9: Protection of Audit Information
# This policy validates that the system:
# a. Protects audit information and audit tools from unauthorized access, modification, and deletion
# b. Implements access controls to limit access to audit information and tools to authorized personnel only

# Check if access controls for audit logs are properly configured
audit_access_controls_configured if {
    # Verify that access controls are enabled
    input.audit_protection.access_controls.enabled == true
    
    # Verify that authorized roles are configured
    count(input.audit_protection.access_controls.authorized_roles) > 0
    
    # Verify that access control mechanisms are configured
    count(input.audit_protection.access_controls.mechanisms) > 0
}

# Check if encryption for audit data is properly configured
audit_encryption_configured if {
    # Verify that encryption is enabled
    input.audit_protection.encryption.enabled == true
    
    # Verify that encryption algorithm is strong
    input.audit_protection.encryption.algorithm in ["AES-256", "AES-192", "AES-128"]
    
    # Verify that encryption keys are properly managed
    input.audit_protection.encryption.key_management.enabled == true
}

# Check if integrity verification for audit logs is properly configured
audit_integrity_configured if {
    # Verify that integrity verification is enabled
    input.audit_protection.integrity.enabled == true
    
    # Verify that integrity mechanisms are configured
    count(input.audit_protection.integrity.mechanisms) > 0
    
    # Verify that integrity verification frequency is appropriate
    input.audit_protection.integrity.verification_frequency_hours <= 24
}

# Check if backup for audit logs is properly configured
audit_backup_configured if {
    # Verify that backup is enabled
    input.audit_protection.backup.enabled == true
    
    # Verify that backup frequency is appropriate
    input.audit_protection.backup.frequency_hours <= 24
    
    # Verify that backup storage is configured
    input.audit_protection.backup.storage_location
    
    # Verify that backup retention is configured
    input.audit_protection.backup.retention_days > 0
}

# Check if protection for audit tools is properly configured
audit_tools_protection_configured if {
    # Verify that tools protection is enabled
    input.audit_protection.tools_protection.enabled == true
    
    # Verify that protection mechanisms are configured
    count(input.audit_protection.tools_protection.mechanisms) > 0
    
    # Verify that authorized roles for tools access are configured
    count(input.audit_protection.tools_protection.authorized_roles) > 0
}

# Check if audit information is protected from unauthorized deletion
deletion_protection_configured if {
    # Verify that deletion protection is enabled
    input.audit_protection.deletion_protection.enabled == true
    
    # Verify that deletion protection mechanisms are configured
    count(input.audit_protection.deletion_protection.mechanisms) > 0
    
    # Verify that deletion requires approval
    input.audit_protection.deletion_protection.requires_approval == true
}

# Check if audit information is protected from unauthorized modification
modification_protection_configured if {
    # Verify that modification protection is enabled
    input.audit_protection.modification_protection.enabled == true
    
    # Verify that modification protection mechanisms are configured
    count(input.audit_protection.modification_protection.mechanisms) > 0
    
    # Verify that modification is logged
    input.audit_protection.modification_protection.log_modifications == true
}

# Final decision on audit protection compliance
audit_protection_compliant if {
    audit_access_controls_configured
    audit_encryption_configured
    audit_integrity_configured
    audit_backup_configured
    audit_tools_protection_configured
    deletion_protection_configured
    modification_protection_configured
}

# Generate detailed compliance report
compliance_report := {
    "audit_access_controls_configured": audit_access_controls_configured,
    "audit_encryption_configured": audit_encryption_configured,
    "audit_integrity_configured": audit_integrity_configured,
    "audit_backup_configured": audit_backup_configured,
    "audit_tools_protection_configured": audit_tools_protection_configured,
    "deletion_protection_configured": deletion_protection_configured,
    "modification_protection_configured": modification_protection_configured,
    "overall_compliant": audit_protection_compliant
}
