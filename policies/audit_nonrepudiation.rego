package security.audit_nonrepudiation

import rego.v1

# AU-10: Non-repudiation
# This policy validates that the system:
# a. Protects against an individual falsely denying having performed a particular action
# b. Provides evidence that an individual performed a particular action (e.g., creating information, 
#    sending a message, approving information, and receiving a message)

# Check if digital signature mechanisms are properly configured
digital_signature_configured if {
    # Verify that digital signatures are enabled
    input.nonrepudiation.digital_signature.enabled == true
    
    # Verify that signature algorithm is strong
    input.nonrepudiation.digital_signature.algorithm in ["RSA-2048", "RSA-3072", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "ECDSA-P521", "Ed25519"]
    
    # Verify that key management is properly configured
    input.nonrepudiation.digital_signature.key_management.enabled == true
}

# Check if identity binding mechanisms are properly configured
identity_binding_configured if {
    # Verify that identity binding is enabled
    input.nonrepudiation.identity_binding.enabled == true
    
    # Verify that binding mechanisms are configured
    count(input.nonrepudiation.identity_binding.mechanisms) > 0
    
    # Verify that identity verification is required
    input.nonrepudiation.identity_binding.identity_verification_required == true
}

# Check if signature validation processes are properly configured
signature_validation_configured if {
    # Verify that signature validation is enabled
    input.nonrepudiation.signature_validation.enabled == true
    
    # Verify that validation mechanisms are configured
    count(input.nonrepudiation.signature_validation.mechanisms) > 0
    
    # Verify that validation is enforced
    input.nonrepudiation.signature_validation.enforce_validation == true
}

# Check if timestamp binding is properly configured
timestamp_binding_configured if {
    # Verify that timestamp binding is enabled
    input.nonrepudiation.timestamp_binding.enabled == true
    
    # Verify that timestamp source is trusted
    input.nonrepudiation.timestamp_binding.trusted_timestamp_source == true
    
    # Verify that timestamp binding is cryptographically secure
    input.nonrepudiation.timestamp_binding.cryptographic_binding == true
}

# Check if evidence collection is properly configured
evidence_collection_configured if {
    # Verify that evidence collection is enabled
    input.nonrepudiation.evidence_collection.enabled == true
    
    # Verify that collection mechanisms are configured
    count(input.nonrepudiation.evidence_collection.mechanisms) > 0
    
    # Verify that evidence is securely stored
    input.nonrepudiation.evidence_collection.secure_storage == true
}

# Check if chain of custody mechanisms are properly configured
chain_of_custody_configured if {
    # Verify that chain of custody is enabled
    input.nonrepudiation.chain_of_custody.enabled == true
    
    # Verify that custody tracking mechanisms are configured
    count(input.nonrepudiation.chain_of_custody.tracking_mechanisms) > 0
    
    # Verify that custody verification is possible
    input.nonrepudiation.chain_of_custody.verification_enabled == true
}

# Check if a specific digital signature is valid
signature_valid if {
    # Check if signature format is valid
    regex.match(input.nonrepudiation.signature_validation.valid_format, input.signature.value)
    
    # Check if signature is from a trusted source
    input.signature.issuer in input.nonrepudiation.signature_validation.trusted_issuers
    
    # Check if signature is not expired
    time.parse_rfc3339_ns(input.signature.expiration) > time.now_ns()
}

# Check if a specific action has proper non-repudiation
action_has_nonrepudiation if {
    # Verify that action has a digital signature
    input.action.signature
    
    # Verify that action has identity binding
    input.action.identity
    
    # Verify that action has a secure timestamp
    input.action.timestamp
    
    # Verify that action has been logged for evidence
    input.action.logged == true
}

# Final decision on non-repudiation compliance
nonrepudiation_compliant if {
    digital_signature_configured
    identity_binding_configured
    signature_validation_configured
    timestamp_binding_configured
    evidence_collection_configured
    chain_of_custody_configured
}

# Generate detailed compliance report
compliance_report := {
    "digital_signature_configured": digital_signature_configured,
    "identity_binding_configured": identity_binding_configured,
    "signature_validation_configured": signature_validation_configured,
    "timestamp_binding_configured": timestamp_binding_configured,
    "evidence_collection_configured": evidence_collection_configured,
    "chain_of_custody_configured": chain_of_custody_configured,
    "overall_compliant": nonrepudiation_compliant
}
