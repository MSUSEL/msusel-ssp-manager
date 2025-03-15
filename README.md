# SSP_Manager

This research project is currently under development. <br />
It runs on Linux (In particular, it is being developed on Ubuntu 22.04 LTS. An iso image for this Ubuntu version can be found here: https://releases.ubuntu.com/jammy/). <br />
In Windows, you can install Ubuntu 22.04 LTS in WSL2. Git clone this repo into your WSL2 file system (/home/userName/). <br />

## Installation
Make sure you have Git, Docker and Docker-Compose installed. (Please see manifests/README.md for kubernetes installation.)<br />
```
git --version
```
```
docker --version
```
```
docker-compose --version
```
If you don't have Git, it can be installed with: <br />
```
sudo apt install git 
```

Docker can be installed with: <br />
```
sudo apt install docker.io
```

Docker-compose can be installed with: <br />
```
sudo apt install docker-compose 
```
Alternatively, you can install the newer Go-based version of docker-compose with
```
sudo apt update
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
mantic stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install docker-compose-plugin
```
Note: with the newer version run commands with "docker compose ", without the hyphen.

Add yourself to the docker group: <br />
```
sudo usermod -aG docker yourUserName 
```

(Restart your machine) <br />

For autocompletion while editing OSCAL documents and highlighting of key or value errors, use VS Code. The project has the json schemas for the OSCAL documents, and we set VS Code to find them.<br />
To install VS Code in Ubuntu:
```
sudo snap install code --classic
```

This project uses the BRON database developed by Hemberg et al. at MIT. The original research for the database can be found as: <br /> 
Hemberg, Erik, Jonathan Kelly, Michal Shlapentokh-Rothman, Bryn Reinstadler, Katherine Xu, Nick Rutar, and Una-May O'Reilly. "Linking threat tactics, techniques, and patterns with defensive weaknesses, vulnerabilities and affected platform configurations for cyber hunting." arXiv preprint arXiv:2010.00533 (2020). <br />

To clone this repository, including a version of the BRON database use: <br />
```
git clone https://github.com/MSUSEL/msusel-ssp-manager.git 
```
Note: The BRON version copied here is from commit 8a18686cab1f024fcadcac74fb13f1240f491b86 of the [BRON project.](https://github.com/ALFA-group/BRON)

Since we will need to have the access to the database container from other containers in this project, it is necessary to create a local docker network:
```
docker network create ssp_network
```
Note: ssp_network is the docker network that is referenced in the docker-compose and Dockerfiles files that will create the project containers. 

To create the graph database containing the different collections of cybersecurity data: <br />
```
cd BRON 
docker-compose up 
```
This command will create two containers. One is an arangodb container that will host our database. The second is a bootstrap container that will populate the database with the data from different cybersecurity collections. (The bootstrap process can take up to 45 mins) <br />

Once bootstrap finishes, you can see the database in your browser at localhost:8529. The username is root and the password is changeme. Select the BRON database. <br />

The BRON DB container must be added to the docker network that we previously created:
```
docker network connect ssp_network brondb
```
Note: if you ever have problems connecting to the BROB DB, make sure that the brondb container is part of the ssp_network:
```
docker network inspect ssp_network
```


Go back to the msusel-ssp-manager directory and go into the oscal-processing directory: <br />
```
cd .. 
cd oscal-processing 
docker build -t oscalprocessing .
```

This command will create a docker image for NIST's OSCAL validation tool. When a file is submitted for validation on the UI, the flask container will spin up a container for the validation tool using this docker image. <br />

To prepare for the execution of the application containers, we need to run a script that will set up an environment variable for the path to the project in your local computer. This script stores the current working directory path in a .env file that will be created. The docker-compose command will read this file and inform the UI container of its location in the host file system.
```
cd ..
cd ./scripts/
chmod +x ./generate-env.sh
./generate-env.sh
cd ..
```



Now we'll add some additional secutity collections to the database and start the tool's frontend and backend contianers. The new collections contain mappings from MITRE ATT&CK Techniques to NIST SP 800-53 security controls. These mappings where done by MITRE Engenuity Center for Threat-Informed Defense (see:https://github.com/center-for-threat-informed-defense/mappings-explorer/). The container will take some time to complete (up to 30 minutes). When it finishes, the new collections will have been added to the database. Again, you can see them at localhost:8529 The container will be removed when finished. The other two containers that are created are a Python Flask backend and a React frontend. The React contianer is the user interface for the tool. The Flask backend receives requests from the frontend and provides all of the tool's functionalities. <br />
In your terminal, in the msusel-ssp-manager directory: <br />
```
docker-compose up
```
Note: for now, after running docker compose once, you have to comment out the driver service in the docker-compose file, as you don't need to run it again. In the future we will just run it independently.
```
#driver:
    #container_name: driver
    #build: ./AttackTechniquesToControls
    #environment:
      #- ARANGO_DB_URL=http://brondb:8529
      #- ARANGO_DB_NAME=BRON
      #- ARANGO_DB_USERNAME=root
      #- ARANGO_DB_PASSWORD=changeme
    #networks:
      #- ssp_network
```

To stop your containers:
```
docker-compose down
```


### Set Schemas in VS Code
Open the project on VS Code and press Ctrl+Shift+P on the keyboard. On the search bar, type "Workspace json settings". Open the file and copy this content to it and save the changes:<br />
```
{
    "json.schemas": [
        
        { "fileMatch": ["/flask/oscal_schemas/assessment-plans/*"], 
        "url": "./flask/oscal_schemas/oscal_assessment-plan_schema.json" },
        { "fileMatch": ["/flask/oscal_schemas/assessment-results/*"],
        "url": "./flask/oscal_schemas/oscal_assessment-results_schema.json" },
        { "fileMatch": ["/flask/oscal_schemas/catalogs/*"],
        "url": "./flask/oscal_schemas/oscal_catalog_schema.json" },
        { "fileMatch": ["/flask/oscal_schemas/components/*"],
        "url": "./flask/oscal_schemas/oscal_component_schema.json" },
        { "fileMatch": ["/flask/oscal_schemas/POAMs/*"],
        "url": "./flask/oscal_schemas/oscal_poam_schema.json" },
        { "fileMatch": ["/flask/oscal_schemas/profiles/*"],
        "url": "./flask/oscal_schemas/oscal_profile_schema.json" },
        { "fileMatch": ["/flask/oscal_schemas/system-security-plans/*"],
        "url": "./flask/oscal_schemas/oscal_ssp_schema.json" }
    ],
    "yaml.schemas": {
        "./flask/oscal_schemas/oscal_assessment-plan_schema.json": ["/flask/oscal_schemas/assessment-plans/*"],
        "./flask/oscal_schemas/oscal_assessment-results_schema.json": ["/flask/oscal_schemas/assessment-results/*"],
        "./flask/oscal_schemas/oscal_catalog_schema.json": ["/flask/oscal_schemas/catalogs/*"],
        "./flask/oscal_schemas/oscal_component_schema.json": ["/flask/oscal_schemas/components/*"],
        "./flask/oscal_schemas/oscal_poam_schema.json": ["/flask/oscal_schemas/POAMs/*"],
        "./flask/oscal_schemas/oscal_profile_schema.json": ["/flask/oscal_schemas/profiles/*"],
        "./flask/oscal_schemas/oscal_ssp_schema.json": ["/flask/oscal_schemas/system-security-plans/*"]
    }
}
```

The application is now ready. <br /><br />

In the /scripts directory, there are scripts that will move your files to their working directories. For now, these need to be started manually. The rely on the inotify package:
```
sudo apt-get install inotify-tools
```
Make sure the scripts have permissions to execute:
```
cd ./scripts/
chmod +x ./watch_catalog.sh
chmod +x ./watch_profile.sh
chmod +x ./watch_ssp.sh
chmod +x ./watch_generatedFiles.sh
chmod +x ./watch_component.sh
chmod +x ./watch_ap.sh
chmod +x ./finish.sh
 ```
And you can start them with:
```
nohup ./watch_catalog.sh > ./logs/watch_catalog.log 2>&1 &
nohup ./watch_profile.sh > ./logs/watch_profile.log 2>&1 &
nohup ./watch_ssp.sh > ./logs/watch_ssp.log 2>&1 &
nohup ./watch_component.sh > ./logs/watch_component.log 2>&1 &
nohup ./watch_ap.sh > ./logs/watch_ap.log 2>&1 &
``` 

Once you finish your work, you can stop your scripts and REMOVE your flask and react containers by running the finish.sh script:
```
./finish.sh
```


I you keep your flask and react containers, going forward, to restart the application, you only need to restart the aragodb container:  <br />
```
docker start arangocontainerID
```

And start your application containers: <br />
```
docker start <flask-container-id>
docker start <react-app-container-id>
```

You can stop them with: <br />
```
docker stop <container-id>
```

The watch scripts have to be started as shown above. <br />

If you prefer to remove your containers after use, you can run docker-compose up and start your scripts as shown above. Your data persists in the volumes shared between the host and the containers so nothing is lost if you remove the containers. <br />


Funding Agency:   <br />

[<img src="https://www.cisa.gov/profiles/cisad8_gov/themes/custom/gesso/dist/images/backgrounds/6fdaa25709d28dfb5cca.svg" width="20%" height="20%">](https://www.cisa.gov/)

