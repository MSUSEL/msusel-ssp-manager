#!/bin/bash

WATCH_DIR="./flask/shared"
SSP_DIR="./flask/oscal_schemas/system-security-plans"
AP_DIR="./flask/oscal_schemas/assessment-plans"

inotifywait -m "$WATCH_DIR" -e close_write -e moved_to |
while read path action file; do
    FILE_PATH="$WATCH_DIR/$file"

    # Check if the file exists and is not zero-length before proceeding
    if [[ -f "$FILE_PATH" && -s "$FILE_PATH" ]]; then
        case "$file" in
            "ssp.yaml")
                mv "$FILE_PATH" "$SSP_DIR"
                echo "$(date '+%Y-%m-%d %H:%M:%S') - Moved $file to $SSP_DIR"
                ;;
            "ap.yaml")
                mv "$FILE_PATH" "$AP_DIR"
                echo "$(date '+%Y-%m-%d %H:%M:%S') - Moved $file to $AP_DIR"
                ;;
            "placeHolder.txt")
                echo "$(date '+%Y-%m-%d %H:%M:%S') - Skipped placeHolder.txt"
                ;;
            *)
                rm "$FILE_PATH"
                echo "$(date '+%Y-%m-%d %H:%M:%S') - Deleted $file from $WATCH_DIR"
                ;;
        esac
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') - File $file not found or is empty"
    fi
done
