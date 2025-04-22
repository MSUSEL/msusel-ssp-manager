package security.authentication

import rego.v1

# IA-2: Identification and Authentication
# Implements multi-factor authentication requirements

# Default deny authentication
default authentication_valid := false

# Check if token is valid
token_is_valid if {
    # Token has not expired
    input.token.payload.exp > input.now
    
    # Token has required fields
    input.token.payload.sub != ""
    input.token.payload.iat != ""
    input.token.payload.jti != ""
}

# Check if MFA was used for authentication
mfa_used if {
    input.authentication.factors >= 2
}

# Validate authentication for regular users
authentication_valid if {
    token_is_valid
    input.user.type == "regular"
    input.authentication.method == "password"
}

# Validate authentication for staff users (requires MFA)
authentication_valid if {
    token_is_valid
    input.user.type == "staff"
    mfa_used
}

# Validate authentication for admin users (requires MFA)
authentication_valid if {
    token_is_valid
    input.user.type == "admin"
    mfa_used
}

# Track failed authentication attempts
track_failed_attempt if {
    not authentication_valid
    {
        "user_id": input.user.id,
        "timestamp": input.now,
        "ip_address": input.request.ip,
        "reason": "Invalid authentication"
    }
}

# Check for brute force attempts
brute_force_detected if {
    # Get recent failed attempts for this user
    recent_failures := [attempt |
        attempt = data.authentication.failed_attempts[_]
        attempt.user_id == input.user.id
        attempt.timestamp > (input.now - 3600) # Within the last hour
    ]
    
    # If more than 5 failures in the last hour, consider it a brute force attempt
    count(recent_failures) > 5
}

# Final authentication decision
allow if {
    authentication_valid
    not brute_force_detected
}
