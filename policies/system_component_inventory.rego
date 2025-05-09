package security.system_component_inventory

import rego.v1

# CM-8: Information System Component Inventory
# This policy validates that the system:
# a. Develops and documents an inventory of system components that accurately reflects the system
# b. Includes all components within the system
# c. Does not include duplicate accounting of components or components assigned to any other system
# d. Is at the level of granularity deemed necessary for tracking and reporting
# e. Includes specified information to achieve system component accountability
# f. Reviews and updates the system component inventory as required

# Check if inventory is complete
inventory_complete if {
    # Verify that inventory exists
    input.inventory.exists == true
    
    # Verify that inventory is documented
    input.inventory.documented == true
    
    # Verify that inventory includes all required components
    count(input.inventory.components) > 0
    
    # Verify that each component has required information
    component_information_complete
}

# Check if component information is complete
component_information_complete if {
    # For each component, check if it has the required information
    count([component |
        component = input.inventory.components[_]
        not component.id
        not component.type
        not component.owner
        not component.location
        not component.status
    ]) == 0
}

# Check if inventory is accurate
inventory_accurate if {
    # Verify that inventory matches actual system state
    input.inventory.matches_actual_state == true
    
    # Verify that inventory was recently verified
    time.parse_rfc3339_ns(input.inventory.last_verified) > time.now_ns() - (30 * 24 * 60 * 60 * 1000000000) # 30 days in nanoseconds
}

# Check if inventory has no duplicates
inventory_no_duplicates if {
    # Get all component IDs
    component_ids := [component.id | component = input.inventory.components[_]]
    
    # Check if there are any duplicate IDs
    count(component_ids) == count({id | id = component_ids[_]})
}

# Check if inventory is at appropriate granularity
inventory_appropriate_granularity if {
    # Verify that inventory granularity is appropriate
    input.inventory.granularity_appropriate == true
    
    # Verify that inventory includes hardware components
    count([component | component = input.inventory.components[_]; component.type == "hardware"]) > 0
    
    # Verify that inventory includes software components
    count([component | component = input.inventory.components[_]; component.type == "software"]) > 0
    
    # Verify that inventory includes firmware components
    count([component | component = input.inventory.components[_]; component.type == "firmware"]) > 0
}

# Check if inventory includes required information
inventory_includes_required_info if {
    # Required information for all components
    required_info := ["id", "type", "owner", "location", "status", "acquisition_date"]
    
    # Check if all components have all required information
    count([component |
        component = input.inventory.components[_]
        some info in required_info
        not component[info]
    ]) == 0
}

# Check if inventory is regularly updated
inventory_regularly_updated if {
    # Verify that inventory has been updated recently
    time.parse_rfc3339_ns(input.inventory.last_updated) > time.now_ns() - (30 * 24 * 60 * 60 * 1000000000) # 30 days in nanoseconds
    
    # Verify that update process is documented
    input.inventory.update_process.documented == true
    
    # Verify that update process includes all required steps
    count(input.inventory.update_process.steps) >= 3
}

# Check if inventory is properly maintained
inventory_properly_maintained if {
    # Verify that inventory maintenance process is documented
    input.inventory.maintenance_process.documented == true
    
    # Verify that inventory maintenance includes regular reviews
    input.inventory.maintenance_process.includes_regular_reviews == true
    
    # Verify that inventory maintenance includes verification
    input.inventory.maintenance_process.includes_verification == true
}

# Check if inventory is properly protected
inventory_properly_protected if {
    # Verify that inventory is protected from unauthorized access
    input.inventory.access_controls.enabled == true
    
    # Verify that inventory changes are logged
    input.inventory.access_controls.changes_logged == true
    
    # Verify that inventory has backup
    input.inventory.has_backup == true
}

# Final decision on inventory compliance
inventory_compliant if {
    inventory_complete
    inventory_accurate
    inventory_no_duplicates
    inventory_appropriate_granularity
    inventory_includes_required_info
    inventory_regularly_updated
    inventory_properly_maintained
    inventory_properly_protected
}
