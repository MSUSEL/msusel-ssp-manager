#!/bin/bash

# Change ownership of the files so that they can be modified by the user.
# Avoid seeing an error message when there are no .json files in the ./flask/shared/ directory, 
# check before the chown command:
if ls ./flask/shared/*.yaml 1> /dev/null 2>&1; then
    chown ${SUDO_UID}:${SUDO_GID} ./flask/shared/*.yaml
else
    echo "No YAML files found, skipping chown operation."
fi

ls -l ./flask/shared/*.yaml


if ls ./flask/shared/*.json 1> /dev/null 2>&1; then
    chown ${SUDO_UID}:${SUDO_GID} ./flask/shared/*.json
else
    echo "No JSON files found, skipping chown operation."
fi

# Move generated files to their working directories.
# -f checks if the file exists and is a regular file. 
# If the file exists, the mv command is executed. 
if [ -f ./flask/shared/ssp.yaml ]; then
    mv ./flask/shared/ssp.yaml ./flask/oscal_schemas/system-security-plans/ssp.yaml
else
    echo "Source file does not exist, skipping move operation."
fi

if [ -f ./flask/shared/ap.yaml ]; then
    mv ./flask/shared/ap.yaml ./flask/oscal_schemas/assessment-plans/ap.yaml
else
    echo "Source file does not exist, skipping move operation."
fi

if [ -f ./flask/shared/profile.yaml ]; then
    mv ./flask/shared/profile.yaml ./flask/oscal_schemas/profiles/profile.yaml
else
    echo "Source file does not exist, skipping move operation."
fi

if [ -f ./flask/shared/ssp.json ]; then
    mv ./flask/shared/ssp.json ./flask/oscal_schemas/system-security-plans/ssp.json
else
    echo "Source file does not exist, skipping move operation."
fi

if [ -f ./flask/shared/ap.json ]; then
    mv ./flask/shared/ap.json ./flask/oscal_schemas/assessment-plans/ap.json
else
    echo "Source file does not exist, skipping move operation."
fi

if [ -f ./flask/shared/profile.json ]; then
    mv ./flask/shared/profile.json ./flask/oscal_schemas/profiles/profile.json
else
    echo "Source file does not exist, skipping move operation."
fi

if [ -f ./flask/shared/controls.json ]; then
    mv ./flask/shared/controls.json ./controls.json
else
    echo "Source file does not exist, skipping move operation."
fi

if [ -f ./flask/shared/cwe.json ]; then
    mv ./flask/shared/cwe.json ./flask/output_vulnerability_effectiveness/cwe.json
else
    echo "Source file does not exist, skipping move operation."
fi