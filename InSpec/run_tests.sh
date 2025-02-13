#!/bin/bash
while true; do
    inspec exec app_opa_integration.rb
    sleep 3600  # Run test every hour
done