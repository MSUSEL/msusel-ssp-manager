#!/bin/bash

# Find the PID of the watch_and_move.sh script
PID=$(ps aux | grep '[w]atch_and_move.sh' | awk '{print $2}')

if [ -z "$PID" ]; then
    echo "watch_and_move.sh is not running."
else
    echo "Found watch_and_move.sh with PID: $PID"
    # Kill the process
    kill $PID
    echo "watch_and_move.sh with PID $PID has been killed."
fi

# Find the PID of the watch_catalog.sh script
PID=$(ps aux | grep '[w]atch_catalog.sh' | awk '{print $2}')

if [ -z "$PID" ]; then
    echo "watch_catalog.sh is not running."
else
    echo "Found watch_catalog.sh with PID: $PID"
    # Kill the process
    kill $PID
    echo "watch_catalog.sh with PID $PID has been killed."
fi

# Find the PID of the watch_profile.sh script
PID=$(ps aux | grep '[w]atch_profile.sh' | awk '{print $2}')

if [ -z "$PID" ]; then
    echo "watch_profile.sh is not running."
else
    echo "Found watch_profile.sh with PID: $PID"
    # Kill the process
    kill $PID
    echo "watch_profile.sh with PID $PID has been killed."
fi

# Find the PID of the watch_ssp.sh script
PID=$(ps aux | grep '[w]atch_ssp.sh' | awk '{print $2}')

if [ -z "$PID" ]; then
    echo "watch_ssp.sh is not running."
else
    echo "Found watch_ssp.sh with PID: $PID"
    # Kill the process
    kill $PID
    echo "watch_ssp.sh with PID $PID has been killed."
fi

# Find the PID of the watch_generate_ssp.sh script
PID=$(ps aux | grep '[w]atch_generate_ssp.sh' | awk '{print $2}')

if [ -z "$PID" ]; then
    echo "watch_generate_ssp.sh is not running."
else
    echo "Found watch_generate_ssp.sh with PID: $PID"
    # Kill the process
    kill $PID
    echo "watch_generate_ssp.sh with PID $PID has been killed."
fi

# Find the PID of the watch_component.sh script
PID=$(ps aux | grep '[w]atch_component.sh' | awk '{print $2}')

if [ -z "$PID" ]; then
    echo "watch_component.sh is not running."
else
    echo "Found watch_component.sh with PID: $PID"
    # Kill the process
    kill $PID
    echo "watch_component.sh with PID $PID has been killed."
fi

# Find the PID of the watch_ap.sh script
PID=$(ps aux | grep '[w]atch_ap.sh' | awk '{print $2}')

if [ -z "$PID" ]; then
    echo "watch_ap.sh is not running."
else
    echo "Found watch_ap.sh with PID: $PID"
    # Kill the process
    kill $PID
    echo "watch_ap.sh with PID $PID has been killed."
fi

# Bring down the containers after use
#docker-compose down
docker-compose down --rmi all