package security.malicious_code_protection

import rego.v1

# SI-3: Malicious Code Protection
# Implements rules to detect and prevent malicious code

# Default deny
default malicious_code_detected := false

# Check for malicious file patterns
malicious_code_detected if {
    # Check for known malicious file extensions
    malicious_extensions := [".exe", ".bat", ".vbs", ".js", ".ps1"]
    input.file.name
    endswith_any(input.file.name, malicious_extensions)
    not input.file.approved
}

# Check for malicious content patterns
malicious_code_detected if {
    # Check for known malicious code patterns
    malicious_patterns := ["eval(", "system(", "exec(", "<script>", "powershell -e"]
    input.file.content
    contains_any(input.file.content, malicious_patterns)
}

# Check for suspicious file size
malicious_code_detected if {
    # Unusually large files might be suspicious
    input.file.size > 10000000  # 10MB
    input.file.type == "document"  # Only for document types
}

# Helper function to check if string ends with any pattern from a list
endswith_any(str, patterns) if {
    some pattern in patterns
    endswith(str, pattern)
}

# Helper function to check if string contains any pattern from a list
contains_any(str, patterns) if {
    some pattern in patterns
    contains(str, pattern)
}

# Determine if file should be blocked
block_file if {
    malicious_code_detected
    not input.file.override
}

# Determine if file should be quarantined
quarantine_file if {
    malicious_code_detected
    input.file.override
}

# Final decision
allow_file if {
    not malicious_code_detected
}
