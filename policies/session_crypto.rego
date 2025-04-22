package security.session_crypto

import rego.v1

# SC-23: Session Authenticity
# SC-12: Cryptographic Key Establishment and Management
# SC-13: Cryptographic Protection

# Check if session token is valid
session_token_valid if {
    # Token exists
    input.session.token
    
    # Token has not expired
    input.session.expiry > input.now
    
    # Token was issued to the correct user
    input.session.user_id == input.user.id
    
    # Token has not been revoked
    not token_revoked
}

# Check if token has been revoked
token_revoked if {
    input.session.token in data.revoked_tokens
}

# Check if session has been inactive too long
session_inactive_too_long if {
    # Get the last activity timestamp
    last_activity := input.session.last_activity
    
    # Calculate inactivity duration in seconds
    inactivity_duration := input.now - last_activity
    
    # Check if inactive for more than 30 minutes (1800 seconds)
    inactivity_duration > 1800
}

# Check if TLS version is acceptable
tls_version_acceptable if {
    # Only TLS 1.2 and above are acceptable
    acceptable_versions := ["TLS 1.2", "TLS 1.3"]
    input.connection.tls_version in acceptable_versions
}

# Check if cipher suite is strong enough
cipher_suite_acceptable if {
    # List of approved cipher suites
    approved_ciphers := [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    ]
    
    input.connection.cipher_suite in approved_ciphers
}

# Check if encryption at rest is properly configured
encryption_at_rest_valid if {
    # Check encryption algorithm
    input.storage.encryption_algorithm == "AES-256"
    
    # Check key management
    input.storage.key_management == "enterprise_kms"
}

# Final session and crypto validation
valid_session if {
    session_token_valid
    not session_inactive_too_long
}

valid_crypto if {
    tls_version_acceptable
    cipher_suite_acceptable
    encryption_at_rest_valid
}
