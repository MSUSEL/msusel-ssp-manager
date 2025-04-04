package security.authentication

import rego.v1

# By default, deny access.
default allow := false

default access_denied := false

# Allow if the token is valid for non-admin resources.
allow if {
    token_is_valid
    not input.resource == "admin" # Only for non-admin resources
}

# Allow if user has admin role for admin resources
allow if {
    token_is_valid
    input.resource == "admin"
    input.token.payload.role == "admin" # Explicitly check for admin role
}

# Rule: Check if the token is valid.
token_is_valid if {
    input.token.payload.exp > input.now # Token expiration time is valid.
    input.token.payload.sub != "" # Token subject is present.
}

# Log access denied for admin resources
access_denied if {
    input.resource == "admin"
    token_is_valid
    not input.token.payload.role == "admin"
}
