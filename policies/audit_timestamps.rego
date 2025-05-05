package security.audit_timestamps

import rego.v1

# AU-8: Time Stamps
# This policy validates that the system:
# a. Uses internal system clocks to generate time stamps for audit records
# b. Records time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or 
#    Greenwich Mean Time (GMT) and meets organization-defined granularity of time measurement

# Check if time source is properly configured
time_source_configured if {
    # Verify that time source is enabled
    input.time_source.enabled == true
    
    # Verify that time source is properly configured
    input.time_source.type in ["internal_clock", "ntp", "gps", "atomic_clock"]
    
    # If using NTP, verify that NTP servers are configured
    input.time_source.type == "ntp" implies count(input.time_source.ntp_servers) > 0
}

# Check if time format is properly configured
time_format_configured if {
    # Verify that time format is ISO 8601 compliant
    input.time_format.standard == "iso8601"
    
    # Verify that time precision is sufficient (milliseconds or better)
    input.time_format.precision in ["millisecond", "microsecond", "nanosecond"]
    
    # Verify that time zone is UTC or can be mapped to UTC
    input.time_format.time_zone in ["UTC", "GMT"] or input.time_format.utc_mapping == true
}

# Check if time synchronization is properly configured
time_sync_configured if {
    # Verify that time synchronization is enabled
    input.time_sync.enabled == true
    
    # Verify that synchronization interval is appropriate (in minutes)
    input.time_sync.interval_minutes <= 1440  # At least daily
    
    # Verify that synchronization sources are configured
    count(input.time_sync.sources) > 0
    
    # Verify that drift tolerance is configured
    input.time_sync.max_drift_ms <= 1000  # Maximum 1 second drift
}

# Check if time stamp validation is properly configured
timestamp_validation_configured if {
    # Verify that timestamp validation is enabled
    input.timestamp_validation.enabled == true
    
    # Verify that validation method is configured
    count(input.timestamp_validation.methods) > 0
}

# Validate a specific timestamp format
timestamp_format_valid if {
    # Check if timestamp is in ISO 8601 format
    regex.match(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$`, input.timestamp)
    
    # Check if timestamp has timezone information (Z or offset)
    regex.match(`(Z|[+-]\d{2}:\d{2})$`, input.timestamp)
}

# Check if audit records have valid timestamps
audit_timestamps_valid if {
    # Verify that audit record has a timestamp
    input.audit_record.timestamp
    
    # Verify that timestamp is in ISO 8601 format
    regex.match(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$`, input.audit_record.timestamp)
    
    # Verify that timestamp has timezone information (Z or offset)
    regex.match(`(Z|[+-]\d{2}:\d{2})$`, input.audit_record.timestamp)
}

# Final decision on time stamps compliance
time_stamps_compliant if {
    time_source_configured
    time_format_configured
    time_sync_configured
    timestamp_validation_configured
}

# Generate detailed compliance report
compliance_report := {
    "time_source_configured": time_source_configured,
    "time_format_configured": time_format_configured,
    "time_sync_configured": time_sync_configured,
    "timestamp_validation_configured": timestamp_validation_configured,
    "overall_compliant": time_stamps_compliant
}
