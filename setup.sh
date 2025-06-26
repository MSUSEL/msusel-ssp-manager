#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
  echo "Docker is not installed. Please install Docker and try again."
  exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker compose &> /dev/null; then
  echo "Docker Compose is not installed. Please install Docker Compose and try again."
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
docker compose up -d
echo "Waiting for BRON bootstrap to complete (this may take up to 45 minutes)..."
echo "You can check progress with: docker logs -f bootstrap"

# Wait for bootstrap to complete 
echo "Monitoring bootstrap progress..."
while docker ps | grep bootstrap > /dev/null; do
  echo "Bootstrap still running... ($(date +%H:%M:%S))"
  sleep 60
done
echo "BRON bootstrap completed"

# Verify BRON database is running
if ! docker ps | grep brondb > /dev/null; then
  echo "Error: BRON database container is not running"
  exit 1
fi

# Connect BRON to the network
echo "Connecting BRON database to ssp_network..."
docker network connect ssp_network brondb || echo "Already connected or connection failed"
cd ..

# Build the OSCAL processing image
echo "Building OSCAL processing image..."
cd oscal-processing
docker build -t oscalprocessing .
if [ $? -ne 0 ]; then
  echo "Failed to build OSCAL processing image"
  exit 1
fi
cd ..

# Build the driver image
echo "Building driver image..."
docker build -t driver ./AttackTechniquesToControls
if [ $? -ne 0 ]; then
  echo "Failed to build driver image"
  exit 1
fi

# Run the driver container
echo "Running driver container..."
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
echo "Starting containers with docker compose..."
docker compose up -d

echo "Setup completed successfully!"
echo "The application UI can be found at http://localhost:3000"
