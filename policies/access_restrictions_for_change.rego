package security.access_restrictions_for_change

import rego.v1

# CM-5: Access Restrictions for Change
# This policy validates that the system:
# a. Enforces access restrictions for changes to the system
# b. Generates, reviews, and protects records of configuration-controlled changes
# c. Implements physical access restrictions for hardware configuration changes

# Check if user is authorized to make changes
user_authorized_for_changes if {
    # Verify that user has appropriate role
    "config_admin" in input.user.roles
}

user_authorized_for_changes if {
    # Verify that user has appropriate role
    "system_admin" in input.user.roles
}

user_authorized_for_changes if {
    # Verify that user has appropriate role
    "security_admin" in input.user.roles
}

# Check if change is properly documented
change_properly_documented if {
    # Verify that change has a ticket ID
    input.change.ticket_id
    
    # Verify that change has a description
    input.change.description
    
    # Verify that change has an approver
    input.change.approved_by
}

# Check if change is within allowed time window
change_within_allowed_time if {
    # Get current time from input
    current_time := time.parse_rfc3339_ns(input.request.time)
    
    # Convert to hours for easier comparison
    hour_index := 3  # Index for hour in the date array
    hour := time.date(current_time)[hour_index]
    
    # Check if within maintenance window (typically 9pm-5am)
    hour >= 21 
}

change_within_allowed_time if {
    # Get current time from input
    current_time := time.parse_rfc3339_ns(input.request.time)
    
    # Convert to hours for easier comparison
    hour_index := 3  # Index for hour in the date array
    hour := time.date(current_time)[hour_index]
    
    # Check if within maintenance window (typically 9pm-5am)
    hour < 5
}

# Check if change follows proper workflow
change_follows_workflow if {
    # Verify that change has been tested
    input.change.tested == true
    
    # Verify that change has been reviewed
    input.change.reviewed == true
    
    # Verify that change has been approved
    input.change.approved == true
}

# Check if change logging is enabled
change_logging_enabled if {
    # Verify that logging is enabled
    input.change_logging.enabled == true
    
    # Verify that logs are protected
    input.change_logging.protected == true
}

# Check if physical access restrictions are in place for hardware changes
physical_access_restrictions_enabled if {
    # Verify that physical access restrictions are enabled
    input.physical_access.enabled == true
    
    # Verify that physical access requires authentication
    input.physical_access.requires_authentication == true
    
    # Verify that physical access is logged
    input.physical_access.logged == true
}

# Check if emergency change process is defined
emergency_change_process_defined if {
    # Verify that emergency change process exists
    input.emergency_change.process_defined == true
    
    # Verify that emergency changes require post-change review
    input.emergency_change.requires_post_review == true
}

# Final decision on change authorization
change_authorized if {
    # User must be authorized
    user_authorized_for_changes
    
    # Change must be properly documented
    change_properly_documented
    
    # Either follow normal workflow or be an emergency change
    change_follows_workflow
}

change_authorized if {
    # User must be authorized
    user_authorized_for_changes
    
    # Change must be properly documented
    change_properly_documented
    
    # Emergency change with proper authorization
    input.change.emergency == true
    input.change.emergency_approved_by
}

# Final decision on access restrictions for change compliance
access_restrictions_compliant if {
    # User authorization
    user_authorized_for_changes
    
    # Change documentation and workflow
    change_properly_documented
    change_follows_workflow
    
    # Logging and monitoring
    change_logging_enabled
    
    # Physical access restrictions (for hardware changes)
    input.change.type == "hardware" 
    physical_access_restrictions_enabled
    
    # Emergency change process
    emergency_change_process_defined
}
