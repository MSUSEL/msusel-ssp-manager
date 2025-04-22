package security.input_validation

import rego.v1

# SI-3: Malicious Code Protection
# SI-7: Software, Firmware, and Information Integrity

# Default deny
default input_valid := false

# Check if input contains SQL injection attempts
sql_injection_detected if {
    # Simple pattern matching for SQL injection
    patterns := [
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "DROP",
        "UNION",
        "--",
        ";"
    ]
    
    # Convert input to uppercase for case-insensitive matching
    input_upper := upper(input.request.data)
    
    # Check if any pattern is found in the input
    pattern := patterns[_]
    contains(input_upper, pattern)
}

# Check if input contains XSS attempts
xss_detected if {
    # Simple pattern matching for XSS
    patterns := [
        "<script",
        "javascript:",
        "onerror=",
        "onload=",
        "eval("
    ]
    
    # Check if any pattern is found in the input
    pattern := patterns[_]
    contains(input.request.data, pattern)
}

# Check if input length is within acceptable limits
input_length_valid if {
    # Get the field type
    field_type := input.field_type
    
    # Get the maximum length for this field type
    max_length := data.field_limits[field_type].max_length
    
    # Check if input length is within limits
    count(input.request.data) <= max_length
}

# Check if input format is valid based on field type
input_format_valid if {
    # Email validation
    input.field_type == "email"
    regex.match(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, input.request.data)
}

input_format_valid if {
    # Date validation (YYYY-MM-DD)
    input.field_type == "date"
    regex.match(`^\d{4}-\d{2}-\d{2}$`, input.request.data)
}

input_format_valid if {
    # Phone number validation
    input.field_type == "phone"
    regex.match(`^\+?[0-9]{10,15}$`, input.request.data)
}

input_format_valid if {
    # For other field types, no specific format validation
    not input.field_type in ["email", "date", "phone"]
}

# Check file integrity using hash
file_integrity_valid if {
    # Get the expected hash for the file
    expected_hash := data.file_hashes[input.file.name]
    
    # Compare with the actual hash
    input.file.hash == expected_hash
}

# Final input validation decision
input_valid if {
    not sql_injection_detected
    not xss_detected
    input_length_valid
    input_format_valid
}
