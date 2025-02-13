#!/bin/bash

# Set up the InSpec license if provided
if [ ! -z "$INSPEC_LICENSE_KEY" ]; then
    echo "Setting up InSpec license..."
    mkdir -p /root/.chef/accepted_licenses
    
    # Create expect script
    cat << 'EOF' > /tmp/license_accept.exp
#!/usr/bin/expect -f
set timeout -1
set license_key [lindex $argv 0]

spawn inspec
expect "Please choose one of the options below"
send "1\r"
expect "Please enter your license ID:"
send "$license_key\r"
expect eof
EOF
    
    chmod +x /tmp/license_accept.exp
    
    # Run expect script with license key
    /tmp/license_accept.exp "$INSPEC_LICENSE_KEY"
    
    echo "License accepted and configured"
else
    echo "Warning: INSPEC_LICENSE_KEY not provided"
    exit 1
fi

# Verify InSpec installation
if ! command -v inspec &> /dev/null; then
    echo "Error: InSpec not found"
    exit 1
fi

# Run the tests
exec ./run_tests.sh
