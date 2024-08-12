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

# Bring down the containers after use
docker-compose down