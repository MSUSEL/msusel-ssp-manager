#!/bin/bash

# Navigate to the directory containing your docker-compose.yml file
# cd /path/to/your/docker-compose/directory

# Ask for the sudo password once
sudo -v

# This script stores the current working directory path in a .env file that will be created. 
# The docker-compose command will read this file and inform the UI container of its location 
# in the host file system.
./generate-env.sh

# Bring up the containers
docker-compose up

# Make scripts executable 
sudo chmod +x generate-env.sh
sudo chmod +x watch_and_move.sh
sudo chmod +x watch_catalog.sh
sudo chmod +x watch_profile.sh
sudo chmod +x watch_ssp.sh
sudo chmod +x watch_generatedFiles.sh
sudo chmod +x watch_component.sh
sudo chmod +x watch_ap.sh
sudo chmod +x finish.sh

# Run the scripts in the background
# Note: if nohup doesn't have an output file for a script, 
# it will create one called nohup.out in the current directory. 
# This process would have to be indenpendently killed to finish.
sudo nohup ./watch_catalog.sh > watch_catalog.log 2>&1 &
sudo nohup ./watch_profile.sh > watch_profile.log 2>&1 &
sudo nohup ./watch_ssp.sh > watch_ssp.log 2>&1 &
sudo nohup ./watch_generatedFiles.sh > watch_generatedFiles.log 2>&1 &
sudo nohup ./watch_component.sh > watch_component.log 2>&1 &
sudo nohup ./watch_ap.sh > watch_ap.log 2>&1 &
