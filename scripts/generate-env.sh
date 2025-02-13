#!/bin/bash

# Check if INSPEC_LICENSE_KEY is set
if [ -z "${INSPEC_LICENSE_KEY}" ]; then
    echo "Warning: INSPEC_LICENSE_KEY environment variable is not set"
    INSPEC_LICENSE_KEY="not-set"
fi

# Generate environment variables and write them to .env file
(
  echo "HOST_VOLUME_PATH=$(dirname $(pwd))" # Current working directory
  echo "HOST_UID=$(id -u)"        # User ID of the current user
  echo "HOST_GID=$(id -g)"        # Group ID of the current user
  echo "DOCKER_GID=$(getent group docker | cut -d: -f3)" # GID of the docker group
  #echo "INSPEC_LICENSE_KEY=${INSPEC_LICENSE_KEY}"
  echo "CHEF_LICENSE=accept-no-persist"
) > $(dirname $(pwd))/.env

# Optional: Print a message indicating success
echo ".env file has been generated."
