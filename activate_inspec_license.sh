#!/bin/bash

# Script to help users activate their InSpec license
# This script runs a simple InSpec test that will trigger the license activation prompt

# Set colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}    InSpec License Activation Helper    ${NC}"
echo -e "${BLUE}=========================================${NC}"
echo

# Check if InSpec is installed
if ! command -v inspec &> /dev/null; then
    echo -e "${RED}Error: InSpec is not installed or not in your PATH${NC}"
    echo -e "Please install InSpec first. See: https://docs.chef.io/inspec/install/"
    exit 1
fi

# Print InSpec version
INSPEC_VERSION=$(inspec --version | head -n 1)
echo -e "${GREEN}InSpec version: ${INSPEC_VERSION}${NC}"
echo

# Instructions
echo -e "${YELLOW}IMPORTANT:${NC} When you run InSpec for the first time, you'll be prompted to activate your license."
echo -e "You'll need to:"
echo -e "  1. Register at ${BLUE}https://www.chef.io/inspec/${NC} to get a license"
echo -e "  2. When prompted, enter the license key you received"
echo
echo -e "This test will run a simple check that will trigger the license activation prompt if needed."
echo -e "After activation, you won't need to do this again."
echo

# Prompt to continue
read -p "Press Enter to continue or Ctrl+C to cancel..."
echo

# Run the simple test
echo -e "${GREEN}Running InSpec test to trigger license activation...${NC}"
echo

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILE="${SCRIPT_DIR}/inspec/license_activation_test.rb"

# Check if test file exists
if [ ! -f "$TEST_FILE" ]; then
    echo -e "${RED}Error: Test file not found at ${TEST_FILE}${NC}"
    exit 1
fi

# Run the test
inspec exec "$TEST_FILE"
EXIT_CODE=$?

echo
if [ $EXIT_CODE -eq 0 ] || [ $EXIT_CODE -eq 100 ]; then
    echo -e "${GREEN}Success!${NC} InSpec ran successfully."
    echo -e "If you were prompted for a license, your InSpec is now activated."
    echo -e "You can now use the SSP Manager's testing features."
else
    echo -e "${RED}There was an issue running InSpec.${NC}"
    echo -e "Exit code: ${EXIT_CODE}"
    echo -e "Please check the output above for more details."
fi

echo
echo -e "${BLUE}=========================================${NC}"