# SSP_Manager

A System Security Plan (SSP) management tool thatintegrates vulnerability assessment with security compliance. The tool identifies NIST SP 800-53 security controls that can mitigate MITRE ATT&CK techniques used to exploit vulnerabilities found in the system. 

## Overview

The SSP Manager provides a pipeline that:

- **Automates SSP Generation**: Creates OSCAL-compliant System Security Plans templates from the compliance profile for a system
- **Vulnerability Analysis**: Scans dependencies and code for security vulnerabilities and weaknesses 
- **Threat Intelligence**: Leverages the BRON database to map vulnerabilities and weaknesses to MITRE ATT&CK techniques and defensive NIST SP 800-53controls
- **Web Interface**: Provides users with a dashboard for visualization and management
- **Standards Compliance**: Validates and processes OSCAL documents (XML, JSON, YAML formats)

The tool is built on MIT's BRON (Bidirectional Relationships for Offensive and Defensive Cyber Operations) database and designed for organizations requiring automated security threat analysis.

## Architecture

- **Backend**: Flask application with Python analysis pipeline
- **Frontend**: React/TypeScript web interface
- **Database**: BRON (ArangoDB) for threat intelligence
- **Standards**: OSCAL 1.0.4 compliance with XML/JSON/YAML support

## Requirements

- **Linux**: Ubuntu 22.04 LTS or newer (tested on 25.04)
  - Download Ubuntu 22.04 LTS: https://releases.ubuntu.com/jammy/
- **Windows**: Ubuntu 22.04 LTS via WSL2
  - Clone this repository to your WSL2 filesystem: `/home/userName/`

## Installation

### Prerequisites
Make sure you have Git, Docker and Docker Compose installed:

```bash
git --version
docker --version
docker compose --version
```

If missing, install them:
```bash
# Git
sudo apt install git

# Docker
sudo apt install docker.io

# Docker Compose (if needed)
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

Add yourself to the docker group and restart:
```bash
sudo usermod -aG docker $USER
# Restart your machine
```

### Quick Setup
Clone the repository and run the automated setup:
```bash
git clone https://github.com/MSUSEL/msusel-ssp-manager.git
cd msusel-ssp-manager
./setup.sh
```

The setup script will:
- Create necessary Docker networks
- Build and start the BRON database (90+ minutes)
- Build OSCAL processing and analysis components
- Start all services

The application UI will be available at http://localhost:3000

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

