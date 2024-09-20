#!/bin/bash

# Bring down the containers after use
docker-compose -f ../docker-compose.yml down --rmi all

# A function that takes the script name as an argument, 
# finds all associated PIDs, and kills them.
kill_processes_by_name() {
    local script_name=$1
    # Find all PIDs related to the script
    # ps aux | grep "[${script_name:0:1}]${script_name:1}": 
    # Uses a trick to prevent grep from matching itself (by using bracketed first letter).
    PIDs=$(ps aux | grep "[${script_name:0:1}]${script_name:1}" | awk '{print $2}')
    
    if [ -z "$PIDs" ]; then
        echo "$script_name is not running."
    else
        echo "Found $script_name with PIDs: $PIDs"
        # Kill all PIDs found
        # xargs -r  kill: Ensures that all PIDs found are passed to kill, 
        # and -r prevents xargs from running kill if no PIDs are found.
        echo "$PIDs" | xargs -r  kill
        echo "$script_name with PIDs $PIDs has been killed."
    fi
}

# Kill all scripts
kill_processes_by_name "watch_and_move.sh"
kill_processes_by_name "watch_catalog.sh"
kill_processes_by_name "watch_profile.sh"
kill_processes_by_name "watch_ssp.sh"
kill_processes_by_name "watch_generatedFiles.sh"
kill_processes_by_name "watch_component.sh"
kill_processes_by_name "watch_ap.sh"

# inotifywait waits for changes to files or directories.
# The above scripts create inotifywait processes to watch for file events.
# The inotifywait processes need to be killed separately.
# Kill any remaining inotifywait processes
inotify_pids=$(ps aux | grep '[i]notifywait' | awk '{print $2}')
if [ -z "$inotify_pids" ]; then
    echo "No inotifywait processes are running."
else
    echo "Found inotifywait processes with PIDs: $inotify_pids"
    echo "$inotify_pids" | xargs -r  kill
    echo "All inotifywait processes have been killed."
fi