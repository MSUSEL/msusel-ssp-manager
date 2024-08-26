#!/bin/bash

WATCH_SSP="./flask/generatedFiles"
SSP_DIR="./flask/oscal_schemas/system-security-plans"
AP_DIR="./flask/oscal_schemas/assessment-plans"

inotifywait -m "$WATCH_SSP" -e close_write -e moved_to |
while read path action file; do
    FILE_PATH="$WATCH_SSP/$file"

    # Check if the file exists and is not zero-length before proceeding
    if [[ -f "$FILE_PATH" && -s "$FILE_PATH" ]]; then
        if [[ "$file" == "generated_ssp.yaml" ]]; then
            mv "$FILE_PATH" "$SSP_DIR"
            echo "$(date '+%Y-%m-%d %H:%M:%S') - Moved $file to $SSP_DIR"
        elif [[ "$file" == "generated_ap.yaml" ]]; then
            mv "$FILE_PATH" "$AP_DIR"
            echo "$(date '+%Y-%m-%d %H:%M:%S') - Moved $file to $AP_DIR"
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') - No matching directory for $file"
        fi
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') - File $file not found or is empty"
    fi
done

