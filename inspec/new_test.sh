#!/bin/bash

# Directory containing InSpec test files (default: current directory)
TEST_DIR="${1:-.}"

# Optional: output summary
PASSED=0
FAILED=0

echo "Running InSpec tests in directory: $TEST_DIR"
echo "--------------------------------------------"

for file in "$TEST_DIR"/*.rb; do
  if [ -f "$file" ]; then
    echo "Running test: $file"
    inspec exec "$file"
    if [ $? -eq 0 ]; then
      echo "✅ Passed: $file"
      ((PASSED++))
    else
      echo "❌ Failed: $file"
      ((FAILED++))
    fi
    echo "--------------------------------------------"
  fi
done

echo "Test Summary:"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
