package security.account_management

import rego.v1

# AC-2: Account Management
# This policy implements comprehensive account management controls including:
# - Account creation with proper approvals
# - Account modification with proper authorization
# - Account disabling/termination processes
# - Account review and monitoring
# - Account expiration enforcement

# Default deny all account management operations
default account_creation_valid := false
default account_modification_valid := false
default account_disabling_valid := false
default account_removal_valid := false
default account_valid := false

# Check if account creation is valid
account_creation_valid if {
    # Verify the creator has admin role
    input.creator.roles[_] == "admin"
    
    # Verify the account has required fields
    input.account.id
    input.account.roles
    
    # Verify proper approval
    input.account.creation.approved_by
    
    # Verify expiration date is set
    input.account.expiration.date
}

# Check if account modification is valid
account_modification_valid if {
    # Verify the modifier has admin role
    input.modifier.roles[_] == "admin"
    
    # Verify the account exists
    input.account.id
    
    # Verify proper approval for role changes
    input.changes.roles
    input.changes.approved_by
}

# Account modification is also valid if users are modifying their own non-privileged information
account_modification_valid if {
    # User is modifying their own account
    input.modifier.id == input.account.id
    
    # Not modifying privileged information (roles, status, etc.)
    not input.changes.roles
    not input.changes.status
}

# Check if account disabling is valid
account_disabling_valid if {
    # Verify the disabler has admin role
    input.disabler.roles[_] == "admin"
    
    # Verify the account exists
    input.account.id
    
    # Verify reason is provided
    input.reason
}

# Check if account removal is valid
account_removal_valid if {
    # Verify the remover has admin role
    input.remover.roles[_] == "admin"
    
    # Verify the account exists
    input.account.id
    
    # Verify proper approval
    input.removal.approved_by
    
    # Verify reason is provided
    input.removal.reason
}

# Check if account is valid (not expired, not disabled)
account_valid if {
    # Account exists and is active
    input.account.status == "active"
    
    # Account has not expired
    not account_expired
}

# Check if account has expired
account_expired if {
    # Current time is after expiration date
    current_time := time.parse_rfc3339_ns(input.current_time)
    expiration_time := time.parse_rfc3339_ns(input.account.expiration.date)
    current_time > expiration_time
}

# Check if account is inactive
account_inactive if {
    input.account.status == "inactive"
}

# Check if account is locked
account_locked if {
    input.account.status == "locked"
}

# Check if account requires review
account_requires_review if {
    # Account has not been reviewed in the last 90 days
    current_time := time.parse_rfc3339_ns(input.current_time)
    last_review_time := time.parse_rfc3339_ns(input.account.last_review)
    
    # Calculate difference in days
    diff_ns := current_time - last_review_time
    diff_days := diff_ns / (24 * 60 * 60 * 1000000000)
    
    diff_days > 90
}

# Check if account has excessive privileges
account_excessive_privileges if {
    # Account has both admin and user roles
    input.account.roles[_] == "admin"
    input.account.roles[_] == "user"
    
    # Account is not a service account
    not input.account.type == "service"
}

# Generate account review report
account_review_report := {
    "expired_accounts": [account.id | account = input.accounts[_]; account_expired with input.account as account],
    "inactive_accounts": [account.id | account = input.accounts[_]; account_inactive with input.account as account],
    "locked_accounts": [account.id | account = input.accounts[_]; account_locked with input.account as account],
    "accounts_requiring_review": [account.id | account = input.accounts[_]; account_requires_review with input.account as account],
    "accounts_with_excessive_privileges": [account.id | account = input.accounts[_]; account_excessive_privileges with input.account as account]
}
