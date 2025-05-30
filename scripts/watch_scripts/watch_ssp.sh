#!/bin/bash

WATCH_SSP="../flask/generateFiles"
SSP_DIR="../flask/oscal_schemas/system-security-plans"

inotifywait -m "$WATCH_SSP" -e close_write -e moved_to |
while read path action file; do
    FILE_PATH="$WATCH_SSP/$file"

    # Check if the file exists and is not zero-length before proceeding
    if [[ -f "$FILE_PATH" && -s "$FILE_PATH" ]]; then
        mv "$FILE_PATH" "$SSP_DIR"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Moved $file to $SSP_DIR"
        # Execute the clean-shared-dir.sh script
        ./clean-shared-dir.sh
        echo "Finished executing clean-shared-dir.sh"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') - File $file not found or is empty"
    fi
done