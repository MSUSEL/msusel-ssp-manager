#!/bin/bash

# Navigate to the directory containing your docker-compose.yml file
# cd /path/to/your/docker-compose/directory

chmod +x generate-env.sh
chmod +x watch_and_move.sh
chmod +x finish.sh

./generate-env.sh

nohup ./watch_and_move.sh > watch_and_move.log 2>&1 &

# Bring up the containers
docker-compose up 

# Check the status of the containers
# docker-compose ps

# Run any additional commands here
# For example, you might want to run a specific service's logs:
# docker-compose logs -f <service_name>

# Optionally, bring down the containers after use
# docker-compose down