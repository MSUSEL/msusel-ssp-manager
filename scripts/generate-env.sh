#!/bin/bash

# Generate environment variables and write them to .env file
(
  echo "HOST_VOLUME_PATH=$(dirname $(pwd))" # Current working directory
  echo "HOST_UID=$(id -u)"        # User ID of the current user
  echo "HOST_GID=$(id -g)"        # Group ID of the current user
) > $(dirname $(pwd))/.env

# Optional: Print a message indicating success
echo ".env file has been generated."