#!/bin/bash

# Create logs directory if it doesn't exist
mkdir -p ./scripts/logs

# Create docker network if it doesn't exist
if ! docker network inspect ssp_network >/dev/null 2>&1; then
  echo "Creating docker network: ssp_network"
  docker network create ssp_network
else
  echo "Docker network ssp_network already exists"
fi

# Set up BRON database
echo "Setting up BRON database..."
cd BRON
echo "Building and starting BRON containers..."
docker-compose up -d
echo "Waiting for BRON bootstrap to complete (this may take up to 45 minutes)..."
echo "You can check progress with: docker logs -f bootstrap"
# Wait for bootstrap to complete
while docker ps | grep bootstrap > /dev/null; do
  echo "Bootstrap still running... waiting"
  sleep 60
done
echo "BRON bootstrap completed"

# Connect BRON to the network
echo "Connecting BRON database to ssp_network..."
docker network connect ssp_network brondb
cd ..

# Build the OSCAL processing image
echo "Building OSCAL processing image..."
cd oscal-processing
docker build -t oscalprocessing .
cd ..

# Generate environment file
echo "Generating environment file..."
cd ./scripts/
chmod +x ./generate-env.sh
./generate-env.sh
cd ..

# Start the containers
echo "Starting containers with docker-compose..."
docker-compose up -d

echo "Waiting for containers to start..."
