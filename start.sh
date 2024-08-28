#!/bin/bash

# Navigate to the directory containing your docker-compose.yml file
# cd /path/to/your/docker-compose/directory

# Ask for the sudo password once
sudo -v

# Make scripts executable with sudo
sudo chmod +x generate-env.sh
sudo chmod +x watch_and_move.sh
sudo chmod +x watch_catalog.sh
sudo chmod +x watch_profile.sh
sudo chmod +x watch_ssp.sh
sudo chmod +x watch_generatedFiles.sh
sudo chmod +x watch_component.sh
sudo chmod +x watch_ap.sh
sudo chmod +x finish.sh

# Run the scripts with sudo in the background
sudo nohup ./generate-env.sh &
sudo nohup ./watch_catalog.sh > watch_catalog.log 2>&1 &
sudo nohup ./watch_profile.sh > watch_profile.log 2>&1 &
sudo nohup ./watch_ssp.sh > watch_ssp.log 2>&1 &
sudo nohup ./watch_generatedFiles.sh > watch_generatedFiles.log 2>&1 &
sudo nohup ./watch_component.sh > watch_component.log 2>&1 &
sudo nohup ./watch_ap.sh > watch_ap.log 2>&1 &

# Bring up the containers with sudo
docker-compose up


# Check the status of the containers
# docker-compose ps

# Run any additional commands here
# For example, you might want to run a specific service's logs:
# docker-compose logs -f <service_name>

# Optionally, bring down the containers after use
# docker-compose down