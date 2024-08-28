#!/bin/bash

# Remove files from one directory without prompting
rm -f ./flask/shared/*.yaml
rm -f ./flask/shared/*.json
rm -f ./flask/shared/*.txt

# Add a necessary placeholder file
echo "Necessary placeholder file." > ./flask/shared/placeHolder.txt
