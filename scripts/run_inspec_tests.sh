#!/bin/bash

# Script to watch for trigger files and run InSpec tests
# This script should run on the host machine, not in the Docker container

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WATCH_DIR="$PROJECT_ROOT/flask/react-app/public/data"
TRIGGER_FILE="$WATCH_DIR/run_tests_trigger.txt"
RESULTS_FILE="$WATCH_DIR/test_results.json"
INSPEC_DIR="$PROJECT_ROOT/inspec"
LOG_FILE="$PROJECT_ROOT/logs/inspec_watcher.log"
TEMP_DIR="/tmp/inspec_$(date +%s)"
PYTHON_PROCESSOR="$SCRIPT_DIR/process_inspec_results.py"

# Create required directories
mkdir -p "$(dirname "$LOG_FILE")" "$WATCH_DIR" "$TEMP_DIR"

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to process InSpec results
process_results() {
    local output_file="$1"

    # Check if output file exists and has content
    if [ ! -f "$output_file" ] || [ ! -s "$output_file" ]; then
        log "WARNING: InSpec output file is empty or not found"
        return 1
    fi

    # Check if output is valid JSON
    if ! jq empty "$output_file" 2>/dev/null; then
        log "WARNING: InSpec output is not valid JSON"
        return 1
    fi

    # Process the results with Python script
    log "Processing InSpec results with Python"

    if [ -f "$PYTHON_PROCESSOR" ]; then
        python3 "$PYTHON_PROCESSOR" "$output_file" "$RESULTS_FILE"
        if [ $? -ne 0 ]; then
            log "ERROR: Failed to process results with Python"
            return 1
        else
            log "Successfully processed InSpec results"
            return 0
        fi
    else
        log "ERROR: Python processor script not found at $PYTHON_PROCESSOR"
        return 1
    fi
}

# Function to run InSpec tests
run_tests() {
    log "Trigger detected. Running InSpec tests..."

    # Using Docker for InSpec execution, no local installation needed

    # Check if InSpec directory exists and has the proper structure
    if [ ! -d "$INSPEC_DIR" ] || [ ! -f "$INSPEC_DIR/inspec.yml" ]; then
        log "WARNING: InSpec directory is not a valid profile"
        exit 1
    fi

    # Use /tmp for temporary files and mount it separately to Docker
    TEMP_DIR="/tmp/inspec_$(date +%s)"
    mkdir -p "$TEMP_DIR"

    # Create output file
    OUTPUT_FILE="$TEMP_DIR/inspec_output.json"

    # Run InSpec in Docker container with verbose output and save the command output for debugging
    # Mount the project root so the container can access InSpec tests and generate output
    log "Running InSpec profile from $INSPEC_DIR using Docker container"
    log "Project root: $PROJECT_ROOT"
    log "Output file: $OUTPUT_FILE"

    # Run InSpec in Docker container
    # Mount project root to /share and temp directory to /tmp in container
    CONTAINER_OUTPUT_FILE="/tmp/$(basename "$TEMP_DIR")/inspec_output.json"
    INSPEC_OUTPUT=$(docker run --rm \
        -v "$PROJECT_ROOT":/share \
        -v "$TEMP_DIR":/tmp/$(basename "$TEMP_DIR") \
        --network host \
        chef/inspec exec /share/inspec \
        --reporter json:"$CONTAINER_OUTPUT_FILE" \
        --log-level debug \
        --chef-license accept 2>&1)
    EXIT_CODE=$?

    # Log the full InSpec output for debugging
    log "InSpec command output:"
    log "$INSPEC_OUTPUT"

    # Check exit code (0 = success, 100 = test failures but command succeeded)
    if [ $EXIT_CODE -eq 0 ] || [ $EXIT_CODE -eq 100 ]; then
        log "Tests completed with exit code $EXIT_CODE"
        if ! process_results "$OUTPUT_FILE"; then
            log "Failed to process test results"
            exit 1
        fi
    else
        log "ERROR: Tests failed with exit code $EXIT_CODE"
        exit 1
    fi

    # For debugging, keep the temp directory
    # Comment this line out when debugging is complete
    # rm -rf "$TEMP_DIR"

    log "InSpec tests completed"
    return 0
}

# Function to watch for trigger file
watch_for_trigger() {
    log "Starting to watch for trigger file: $TRIGGER_FILE"

    while true; do
        # Check if trigger file exists
        if [ -f "$TRIGGER_FILE" ]; then
            TRIGGER_TIME=$(cat "$TRIGGER_FILE")
            log "Trigger file found with timestamp: $TRIGGER_TIME"

            # Remove trigger file
            rm -f "$TRIGGER_FILE"

            # Run tests
            run_tests
        fi

        # Sleep for a short time before checking again
        sleep 1
    done
}

# Main function
main() {
    log "Starting InSpec test watcher"
    log "==========================="
    log "Configuration:"
    log "  Script directory: $SCRIPT_DIR"
    log "  Project root: $PROJECT_ROOT"
    log "  Watch directory: $WATCH_DIR"
    log "  Trigger file: $TRIGGER_FILE"
    log "  Results file: $RESULTS_FILE"
    log "  InSpec directory: $INSPEC_DIR"
    log "  Log file: $LOG_FILE"
    log "  Python processor: $PYTHON_PROCESSOR"
    log "==========================="

    # Check if Python processor exists
    if [ ! -f "$PYTHON_PROCESSOR" ]; then
        log "ERROR: Python processor script not found at $PYTHON_PROCESSOR"
        log "Please create this file before running the script"
        exit 1
    fi

    # Make Python processor executable
    chmod +x "$PYTHON_PROCESSOR"

    # Check Docker installation and InSpec image availability
    if command -v docker &> /dev/null; then
        DOCKER_VERSION=$(docker --version)
        log "Docker is installed: $DOCKER_VERSION"

        # Check if InSpec Docker image is available
        log "Checking InSpec Docker image availability..."
        INSPEC_IMAGE_CHECK=$(docker run --rm chef/inspec --version 2>&1)
        if [ $? -eq 0 ]; then
            log "InSpec Docker image is available: $(echo "$INSPEC_IMAGE_CHECK" | head -n 1)"
        else
            log "WARNING: Failed to run InSpec Docker image"
            log "Error: $INSPEC_IMAGE_CHECK"
        fi
    else
        log "ERROR: Docker is not installed or not in PATH"
        log "Docker is required to run InSpec tests"
        exit 1
    fi

    # Start watching for trigger file
    watch_for_trigger
}

# Run the main function
main
