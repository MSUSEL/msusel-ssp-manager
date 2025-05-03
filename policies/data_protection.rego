package security.data_protection

import rego.v1

# SC-28: Protection of Information at Rest
# Implements rules to ensure data at rest is properly protected

# Default deny
default data_encryption_valid := false
default key_management_valid := false
default access_control_valid := false

# Check if data encryption is valid
data_encryption_valid if {
    # Ensure encryption is enabled
    input.storage.encryption.enabled == true
    
    # Ensure strong encryption algorithm is used (AES-256 or better)
    strong_algorithms := ["AES-256", "AES-256-GCM", "AES-256-CBC"]
    input.storage.encryption.algorithm in strong_algorithms
}

# Check if key management is valid
key_management_valid if {
    # Ensure key management system is enterprise-grade
    enterprise_systems := ["enterprise_kms", "hardware_security_module", "cloud_kms"]
    input.storage.key_management.system in enterprise_systems
    
    # Ensure key rotation is enabled
    input.storage.key_management.key_rotation_enabled == true
    
    # Ensure key access is restricted
    input.storage.key_management.access_restricted == true
}

# Check if access control to storage is valid
access_control_valid if {
    # Ensure access is restricted to authorized personnel
    input.storage.access_control.enabled == true
    
    # Ensure principle of least privilege is enforced
    input.storage.access_control.least_privilege == true
    
    # Ensure there are no shared credentials
    input.storage.access_control.shared_credentials == false
}

# Overall protection of data at rest is valid if all checks pass
protection_valid if {
    data_encryption_valid
    key_management_valid
    access_control_valid
}

# Final decision for data protection
allow if {
    protection_valid
}
