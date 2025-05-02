package security.boundary_protection

import future.keywords.in

# Default deny
default allow_network_traffic = false
default firewall_rules_valid = false
default network_segmentation_valid = false
default intrusion_detection_active = false
default boundary_monitoring_active = false

# Allow network traffic if source is trusted and destination is allowed
allow_network_traffic {
    # Check if source IP is in allowed list
    input.traffic.source_ip in data.trusted_sources

    # Check if destination is allowed for this source
    some i
    data.allowed_destinations[i].source == input.traffic.source_type
    input.traffic.destination in data.allowed_destinations[i].destinations
}

# Validate firewall rules
firewall_rules_valid {
    # Ensure firewall is enabled
    input.firewall.enabled == true
    
    # Ensure default deny policy is in place
    input.firewall.default_policy == "deny"
    
    # Ensure there are explicit rules
    count(input.firewall.rules) > 0
    
    # Ensure no overly permissive rules
    not has_overly_permissive_rules
}

# Check for overly permissive rules
has_overly_permissive_rules {
    some i
    rule := input.firewall.rules[i]
    rule.source == "any"
    rule.destination == "any"
    rule.port == "any"
    rule.action == "allow"
}

# Validate network segmentation
network_segmentation_valid {
    # Ensure network zones are defined
    count(input.network.zones) >= 2
    
    # Ensure zones have proper access controls between them
    all_zones_have_access_controls
}

# Check that all zones have access controls
all_zones_have_access_controls {
    # For each pair of zones, there should be an access control
    count([x | 
        zone1 := input.network.zones[_]
        zone2 := input.network.zones[_]
        zone1.name != zone2.name
        x := has_access_control(zone1.name, zone2.name)
    ]) == (count(input.network.zones) * (count(input.network.zones) - 1))
}

# Check if there's an access control between two zones
has_access_control(zone1, zone2) = true {
    some i
    input.network.access_controls[i].source == zone1
    input.network.access_controls[i].destination == zone2
}

# Check if intrusion detection is active
intrusion_detection_active {
    input.security.ids.enabled == true
    input.security.ids.updated_within_days <= 7  # Signatures updated within last week
    input.security.ids.monitoring_active == true
}

# Check if boundary monitoring is active
boundary_monitoring_active {
    input.monitoring.boundary.enabled == true
    input.monitoring.boundary.alert_on_unauthorized == true
    count(input.monitoring.boundary.monitored_points) > 0
}

# Sample data for testing
trusted_sources = [
    "192.168.1.0/24",
    "10.0.0.0/8",
    "172.16.0.0/12"
]

allowed_destinations = [
    {
        "source": "internal",
        "destinations": ["web", "api", "database"]
    },
    {
        "source": "dmz",
        "destinations": ["web"]
    },
    {
        "source": "external",
        "destinations": ["web"]
    }
]
