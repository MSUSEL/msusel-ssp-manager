#!/bin/bash

WATCH_CATALOG="./flask/processing/catalog"
CATALOG_DIR="./flask/oscal_schemas/catalogs"

inotifywait -m "$WATCH_CATALOG" -e close_write -e moved_to |
while read path action file; do
    FILE_PATH="$WATCH_CATALOG/$file"

    # Check if the file exists and is not zero-length before proceeding
    if [[ -f "$FILE_PATH" && -s "$FILE_PATH" ]]; then
        sudo chown ${SUDO_UID}:${SUDO_GID} ./flask/processing/catalog/*.yaml
        sudo chown ${SUDO_UID}:${SUDO_GID} ./flask/processing/catalog/*.json
        mv "$FILE_PATH" "$CATALOG_DIR"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Moved $file to $CATALOG_DIR"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') - File $file not found or is empty"
    fi
done
./clean-shared-dir.sh