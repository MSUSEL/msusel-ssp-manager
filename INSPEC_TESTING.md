# InSpec Testing Setup

This document explains how to set up and use the InSpec testing integration with the SSP Manager application.

## Overview

The SSP Manager application allows you to run InSpec tests to validate security controls directly from the UI. Due to licensing constraints, InSpec tests run on the host machine rather than in the Docker container.

## Directory Structure

- `inspec/` - Contains InSpec test files (at the project root)
- `run_inspec_tests.sh` - Host script that watches for trigger files and runs InSpec tests
- `flask/app/test_runner.py` - Flask backend endpoint that triggers tests and returns results
- `flask/react-app/src/components/CurrentStatus.tsx` - React component that displays test results

## Setup Instructions

### 1. Create the InSpec Directory

Create an `inspec` directory at the project root and add your InSpec test files:

```bash
# Create the directory
mkdir -p inspec

# Add your InSpec test files
# Example: touch inspec/controls.rb
```

### 2. Install InSpec on the Host Machine

If you haven't already, install InSpec on your host machine:

```bash
# For Ubuntu/Debian
curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec

# For macOS with Homebrew
brew install chef/chef/inspec

# Verify installation
inspec --version
```

### 3. Create the Shared Data Directory

Create the shared data directory that will be used for communication between the container and host:

```bash
mkdir -p flask/react-app/public/data
```

### 4. Start the Watcher Script

Before starting the Docker containers, start the watcher script on the host machine:

```bash
# Make the script executable (if not already)
chmod +x run_inspec_tests.sh

# Run the script in the background
./run_inspec_tests.sh &
```

This script will watch for trigger files and run InSpec tests when requested.

### 5. Start the Application

Start the application using Docker Compose:

```bash
docker-compose up
```

### 6. Check the Logs

Check the watcher script logs to make sure it's running correctly:

```bash
cat logs/inspec_watcher.log
```

## Using the Testing Feature

1. Navigate to the "Current Status" page in the application
2. Click the "Run Tests" button to trigger InSpec tests
3. The application will display the test results once they are available

## How It Works

1. When you click "Run Tests" in the UI, the React component sends a request to the Flask backend
2. The Flask backend creates a trigger file in a shared volume
3. The host script detects the trigger file and runs InSpec tests
4. Test results are saved to a JSON file in the shared volume
5. The Flask backend reads the results and returns them to the UI
6. The UI displays the test results

## Troubleshooting

### Tests Not Running

If tests don't run when you click the "Run Tests" button:

1. Check if the watcher script is running:
   ```bash
   ps aux | grep run_inspec_tests.sh
   ```

2. Check the watcher script logs:
   ```bash
   cat logs/inspec_watcher.log
   ```

3. Check if the trigger file is being created:
   ```bash
   # After clicking "Run Tests", check if the file exists
   ls -la flask/react-app/public/data/run_tests_trigger.txt
   ```

4. Check the Flask backend logs for errors:
   ```bash
   docker logs flask-backend
   ```

5. Ensure the shared volume is properly mounted and accessible to both the container and host:
   ```bash
   # Create a test file in the shared directory from the host
   echo "test" > flask/react-app/public/data/test_from_host.txt

   # Check if it's visible in the container
   docker exec flask-backend ls -la /app/react-app/public/data/
   ```

### InSpec Errors

If InSpec tests fail to run:

1. Verify InSpec is installed and in your PATH:
   ```bash
   inspec --version
   ```

2. Check if the InSpec directory exists and contains valid tests:
   ```bash
   ls -la inspec/
   ```

3. Try running the tests manually:
   ```bash
   inspec exec inspec/ --reporter json
   ```

4. Check for permission issues:
   ```bash
   # Make sure the current user can write to the data directory
   touch flask/react-app/public/data/test_permissions.txt

   # Make sure InSpec can write to the data directory
   sudo -u $(whoami) inspec exec inspec/ --reporter json -o flask/react-app/public/data/test_output.json
   ```

### Path Issues

If the paths don't align between the host and container:

1. Print the absolute paths in both environments:
   ```bash
   # On the host
   realpath flask/react-app/public/data

   # In the container
   docker exec flask-backend realpath /app/react-app/public/data
   ```

2. Update the paths in the scripts accordingly

## Customizing Tests

To add or modify InSpec tests:

1. Edit or add test files in the `inspec/` directory
2. The tests will be automatically picked up the next time you click "Run Tests"

## Logs

- Host script logs: `logs/inspec_watcher.log`
- Flask backend logs: Available in the Docker container logs
- Test results: `flask/react-app/public/data/test_results.json`
