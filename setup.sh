#!/bin/bash

# Executes the commands in the README.md
# Must be tested

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
  echo "Docker is not installed. Please install Docker and try again."
  exit 1
fi

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

# Build the driver image
echo "Building driver image..."
docker build -t driver ./AttackTechniquesToControls

# Run the driver container
docker run --rm \
  --name driver \
  --network ssp_network \
  -e ARANGO_DB_URL=http://brondb:8529 \
  -e ARANGO_DB_NAME=BRON \
  -e ARANGO_DB_USERNAME=root \
  -e ARANGO_DB_PASSWORD=changeme \
  driver

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
