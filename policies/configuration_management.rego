package security.configuration_management

import rego.v1

# CM-2: Baseline Configuration
# CM-5: Access Restrictions for Change
# CM-8: Information System Component Inventory

# Check if configuration change is authorized
config_change_authorized if {
    # Check if user has permission to make changes
    "config_admin" in input.user.roles

    # Check if change is within allowed hours
    hour_index := 3  # Index for hour in the date array
    current_hour := time.date(time.parse_rfc3339_ns(input.request.time))[hour_index]
    current_hour >= 9
    current_hour < 17

    # Check if change follows change management process
    input.change.ticket_id
    input.change.approved_by
}

# Check if configuration is compliant with baseline
config_compliant_with_baseline if {
    # Get the baseline configuration for this component
    baseline := data.baselines[input.component.type]

    # Check each setting against the baseline
    count([setting |
        setting = baseline.settings[_]
        input.component.settings[setting.name] != setting.value
    ]) == 0
}

# Check if component is in the approved inventory
component_in_inventory if {
    # Get the component ID
    component_id := input.component.id

    # Check if component exists in inventory
    data.inventory[component_id]
}

# Check if component has required security settings
component_security_compliant if {
    # Required security settings for all components
    required_settings := [
        "auto_update",
        "firewall_enabled",
        "antivirus_enabled"
    ]

    # Check if all required settings are present and enabled
    count([setting |
        setting = required_settings[_]
        not input.component.settings[setting]
    ]) == 0
}

# Check if software dependencies are approved
dependencies_approved if {
    # Get all dependencies
    dependencies := input.component.dependencies

    # Check if any dependency is not in the approved list
    count([dep |
        dep = dependencies[_]
        not dep in data.approved_dependencies
    ]) == 0
}

# Final configuration management decision
valid_configuration if {
    component_in_inventory
    config_compliant_with_baseline
    component_security_compliant
    dependencies_approved
}

valid_change if {
    config_change_authorized
}
