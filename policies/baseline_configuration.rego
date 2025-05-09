package security.baseline_configuration

import rego.v1

# CM-2: Baseline Configuration
# This policy validates that the system:
# a. Develops, documents, and maintains a current baseline configuration of the system
# b. Reviews and updates the baseline configuration as needed when required
# c. Maintains the baseline configuration under configuration control

# Check if baseline configuration is properly documented
baseline_documented if {
    # Verify that baseline configuration exists
    input.baseline_configuration.exists == true
    
    # Verify that baseline configuration is documented
    input.baseline_configuration.documented == true
    
    # Verify that baseline configuration includes all required components
    count(input.baseline_configuration.components) > 0
    
    # Verify that each component has required settings
    component_settings_complete
}

# Check if component settings are complete
component_settings_complete if {
    # For each component, check if it has the required settings
    count([component |
        component = input.baseline_configuration.components[_]
        not component.settings
    ]) == 0
}

# Check if baseline configuration is current
baseline_current if {
    # Verify that baseline configuration has been updated recently
    time.parse_rfc3339_ns(input.baseline_configuration.last_updated) > time.parse_rfc3339_ns(input.baseline_configuration.last_review) - (90 * 24 * 60 * 60 * 1000000000) # 90 days in nanoseconds
    
    # Verify that baseline configuration matches current system state
    input.baseline_configuration.matches_current_state == true
}

# Check if baseline configuration is reviewed regularly
baseline_reviewed if {
    # Verify that baseline configuration has been reviewed recently
    time.parse_rfc3339_ns(input.baseline_configuration.last_review) > time.now_ns() - (90 * 24 * 60 * 60 * 1000000000) # 90 days in nanoseconds
    
    # Verify that review process is documented
    input.baseline_configuration.review_process.documented == true
    
    # Verify that review includes all required steps
    count(input.baseline_configuration.review_process.steps) >= 3
}

# Check if baseline configuration is under configuration control
baseline_controlled if {
    # Verify that configuration control is enabled
    input.baseline_configuration.configuration_control.enabled == true
    
    # Verify that change management process is documented
    input.baseline_configuration.configuration_control.change_management.documented == true
    
    # Verify that approvals are required for changes
    input.baseline_configuration.configuration_control.change_management.requires_approval == true
    
    # Verify that changes are tracked
    input.baseline_configuration.configuration_control.change_management.changes_tracked == true
}

# Check if baseline configuration changes are authorized
baseline_change_authorized if {
    # Verify that the user has permission to make changes
    "config_admin" in input.user.roles
    
    # Verify that change is documented
    input.change.documented == true
    
    # Verify that change has been approved
    input.change.approved == true
    
    # Verify that change follows change management process
    input.change.follows_process == true
    
    # Verify that change has a ticket ID
    input.change.ticket_id
}

# Check if baseline configuration is monitored for unauthorized changes
baseline_monitored if {
    # Verify that monitoring is enabled
    input.baseline_configuration.monitoring.enabled == true
    
    # Verify that monitoring is automated
    input.baseline_configuration.monitoring.automated == true
    
    # Verify that alerts are configured for unauthorized changes
    input.baseline_configuration.monitoring.alerts_configured == true
}

# Final decision on baseline configuration compliance
baseline_configuration_compliant if {
    baseline_documented
    baseline_current
    baseline_reviewed
    baseline_controlled
    baseline_monitored
}

# Final decision on baseline configuration change authorization
baseline_change_compliant if {
    baseline_change_authorized
}
