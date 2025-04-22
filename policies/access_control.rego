package security.access_control

import rego.v1

# AC-2: Account Management
# Implements role-based access control (RBAC) to enforce least privilege

# Default deny all access
default allow_access := false

# Check if user has required role for the resource
allow_access if {
    # Verify user exists and is active
    input.user.status == "active"

    # Get the roles assigned to the user
    roles := input.user.roles

    # Get the required roles for the resource
    required_roles := data.resources[input.resource].required_roles

    # Check if user has at least one of the required roles
    count([r | r = roles[_]; r = required_roles[_]]) > 0
}

# AC-3: Access Enforcement
# Enforces approved authorizations for logical access

# Check if access should be denied due to time restrictions
time_restricted if {
    # Get current time from input
    current_time := time.parse_rfc3339_ns(input.request.time)

    # Convert to hours and minutes for easier comparison
    hour_index := 3  # Index for hour in the date array
    hour := time.date(current_time)[hour_index]

    # Check if outside business hours (9am-5pm)
    hour < 9
}

time_restricted if {
    current_time := time.parse_rfc3339_ns(input.request.time)
    hour_index := 3  # Index for hour in the date array
    hour := time.date(current_time)[hour_index]
    hour >= 17
}

# Deny access outside business hours for non-admin users
deny_access if {
    time_restricted
    not admin_user
}

# Check if user is an admin
admin_user if {
    "admin" in input.user.roles
}

# Final access decision
allow if {
    allow_access
    not deny_access
}

# Log access attempts
log_access_attempt if {
    input.action == "access_resource"
    {
        "timestamp": input.request.time,
        "user": input.user.id,
        "resource": input.resource,
        "action": input.action,
        "allowed": allow
    }
}
