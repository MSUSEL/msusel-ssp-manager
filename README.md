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
docker compose --version
```
If you don't have Git, it can be installed with: <br />
```
sudo apt install git
```

Docker can be installed with: <br />
```
sudo apt install docker.io
```

Docker compose can be installed with: <br />
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

Add yourself to the docker group: <br />
```
sudo usermod -aG docker yourUserName
```

(Restart your machine) <br />

This project uses the BRON database developed by Hemberg et al. at MIT. The original research for the database can be found as: <br />
Hemberg, Erik, Jonathan Kelly, Michal Shlapentokh-Rothman, Bryn Reinstadler, Katherine Xu, Nick Rutar, and Una-May O'Reilly. "Linking threat tactics, techniques, and patterns with defensive weaknesses, vulnerabilities and affected platform configurations for cyber hunting." arXiv preprint arXiv:2010.00533 (2020). <br />

To clone this repository, including a version of the BRON database use: <br />
```
git clone https://github.com/MSUSEL/msusel-ssp-manager.git
```
Note: The BRON version copied here is from commit 8a18686cab1f024fcadcac74fb13f1240f491b86 of the [BRON project.](https://github.com/ALFA-group/BRON)


To install the project, run the setup script: <br />
```
./setup.sh
```
The application UI can be found at localhost:3000 <br />

To stop your containers:
```
docker compose down
```

After installing, you can run the project with: <br />
```
docker compose up
```

### Set Schemas in VS Code
For autocompletion while editing OSCAL documents and highlighting of key or value errors, use VS Code. The project has the json schemas for the OSCAL documents, and we set VS Code to find them.
To install VS Code in Ubuntu:
```
sudo snap install code --classic
```
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


Your data persists in the volumes shared between the host and the containers. <br />


Funding Agency:   <br />

[<img src="https://www.cisa.gov/profiles/cisad8_gov/themes/custom/gesso/dist/images/backgrounds/6fdaa25709d28dfb5cca.svg" width="20%" height="20%">](https://www.cisa.gov/)

