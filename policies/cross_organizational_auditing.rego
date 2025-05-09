package security.cross_organizational_auditing

import rego.v1

# AU-16: Cross-Organizational Auditing
# This policy validates that the system:
# a. Employs methods for coordinating audit information among external organizations when audit information is transmitted across organizational boundaries
# b. Preserves the identity of individuals in cross-organizational audit trails

# Check if cross-organizational auditing is enabled
cross_org_auditing_enabled if {
    # Verify that cross-organizational auditing is enabled
    input.cross_org_auditing.enabled == true
    
    # Verify that external organizations are configured
    count(input.cross_org_auditing.external_organizations) > 0
}

# Check if coordination methods are properly configured
coordination_methods_configured if {
    # Verify that coordination methods are configured
    count(input.cross_org_auditing.coordination_methods) > 0
    
    # Verify that at least one coordination method is enabled
    enabled_methods := [method | method = input.cross_org_auditing.coordination_methods[_]; method.enabled == true]
    count(enabled_methods) > 0
}

# Check if audit information sharing is properly configured
audit_sharing_configured if {
    # Verify that audit sharing is enabled
    input.cross_org_auditing.audit_sharing.enabled == true
    
    # Verify that sharing protocols are configured
    count(input.cross_org_auditing.audit_sharing.protocols) > 0
    
    # Verify that sharing frequency is configured
    input.cross_org_auditing.audit_sharing.frequency
}

# Check if identity preservation is properly configured
identity_preservation_configured if {
    # Verify that identity preservation is enabled
    input.cross_org_auditing.identity_preservation.enabled == true
    
    # Verify that identity preservation method is configured
    input.cross_org_auditing.identity_preservation.method
    
    # Verify that identity verification is configured
    input.cross_org_auditing.identity_preservation.verification_enabled == true
}

# Check if secure transmission is properly configured
secure_transmission_configured if {
    # Verify that secure transmission is enabled
    input.cross_org_auditing.secure_transmission.enabled == true
    
    # Verify that encryption is enabled
    input.cross_org_auditing.secure_transmission.encryption_enabled == true
    
    # Verify that encryption protocol is configured
    input.cross_org_auditing.secure_transmission.encryption_protocol
}

# Check if agreements with external organizations are properly configured
agreements_configured if {
    # Verify that agreements are configured
    count(input.cross_org_auditing.agreements) > 0
    
    # Verify that all agreements have required fields
    missing_fields := [agreement |
        agreement = input.cross_org_auditing.agreements[_]
        not agreement.organization_id
        not agreement.agreement_type
        not agreement.effective_date
        not agreement.status == "active"
    ]
    
    count(missing_fields) == 0
}

# Check if a specific external organization is configured for cross-organizational auditing
organization_configured_for_auditing if {
    # Check if the organization is in the list of external organizations
    input.organization.id in [org.id | org = input.cross_org_auditing.external_organizations[_]]
}

# Check if a specific audit record should be shared with external organizations
audit_record_should_be_shared if {
    # Check if the record type is configured for sharing
    input.audit_record.type in input.cross_org_auditing.audit_sharing.record_types_to_share
}

# Final decision on cross-organizational auditing compliance
cross_org_auditing_compliant if {
    cross_org_auditing_enabled
    coordination_methods_configured
    audit_sharing_configured
    identity_preservation_configured
    secure_transmission_configured
    agreements_configured
}
