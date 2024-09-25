#!/bin/bash

# Used to watch and notify changes to directories shared between the host and the containers
#sudo apt-get install inotify-tools

# This script stores the current working directory path in a .env file that will be created. 
# The docker-compose command will read this file and inform the UI container of its location 
# in the host file system.
chmod +x ./generate-env.sh
./generate-env.sh

# Bring up the containers
docker-compose -f ../docker-compose.yml up

# Make scripts executable 
 chmod +x ./watch_and_move.sh
 chmod +x ./watch_catalog.sh
 chmod +x ./watch_profile.sh
 chmod +x ./watch_ssp.sh
 chmod +x ./watch_generatedFiles.sh
 chmod +x ./watch_component.sh
 chmod +x ./watch_ap.sh
 chmod +x ./finish.sh

# Run the scripts in the background
# Note: if nohup doesn't have an output file for a script, 
# it will create one called nohup.out in the current directory. 
# This process would have to be indenpendently killed to finish.
 
# Start the watch_catalog.sh script
echo "Starting watch_catalog.sh"
nohup ./watch_catalog.sh > ./logs/watch_catalog.log 2>&1 &
echo "Started watch_catalog.sh"

# Start the watch_profile.sh script
echo "Starting watch_profile.sh"
nohup ./watch_profile.sh > ./logs/watch_profile.log 2>&1 &
echo "Started watch_profile.sh"

# Start the watch_ssp.sh script
echo "Starting watch_ssp.sh"
nohup ./watch_ssp.sh > ./logs/watch_ssp.log 2>&1 &
echo "Started watch_ssp.sh"

# Start the watch_generatedFiles.sh script
echo "Starting watch_generatedFiles.sh"
nohup ./watch_generatedFiles.sh > ./logs/watch_generatedFiles.log 2>&1 &
echo "Started watch_generatedFiles.sh"

# Start the watch_component.sh script
echo "Starting watch_component.sh"
nohup ./watch_component.sh > ./logs/watch_component.log 2>&1 &
echo "Started watch_component.sh"

# Start the watch_ap.sh script
echo "Starting watch_ap.sh"
nohup ./watch_ap.sh > ./logs/watch_ap.log 2>&1 &
echo "Started watch_ap.sh"

echo "All scripts have been started."