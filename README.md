# SSP_Manager

This research proyect is currently under development. <br />


INSTALL SECTION
Command to copy the repo, including the BRON submodule:
git clone --recurse-submodules <repository-url>
It runs only on Linux (In particular, it is being developed on Ubuntu 22.04). <br />

To run the proyect, you need to have installed Git, Docker and Docker-compose. <br />

Git can be installed with: <br />
sudo apt install git <br />

Docker can be installed with: <br />
sudo apt install docker.io <br />

Docker-compose can be installed with: <br />
sudo apt install docker-compose <br />

Add yourself to the docker group: <br />
sudo usermod -aG docker yourUserName <br />
(Restart your machine) <br />

Now we're going to create the graph database that we'll use to map the different collections of cybersecurity data: <br />
cd BRON <br />
docker-compose up <br />

This command will create two containers. One is an arangodb container that will host our db. The second is a bootstrap container that will populate the db with the data from different cybersecurity collections. (The bootstrap process can take up to 45 mins) <br />
The original research that produced this db was performed by: Hemberg, Erik, Jonathan Kelly, Michal Shlapentokh-Rothman, Bryn Reinstadler, Katherine Xu, Nick Rutar, and Una-May O'Reilly. "Linking threat tactics, techniques, and patterns with defensive weaknesses, vulnerabilities and affected platform configurations for cyber hunting." arXiv preprint arXiv:2010.00533 (2020). <br />

Once the bootstrap finishes, you can see the database in your browser at localhost:8529. The username is root and the password is changeme. Select the BRON database. <br />

Go back to the SSP_Manager folder: <br />
cd .. <br />

And go into the SSP_Demo folder: <br />
cd SSP_Demo <br />

Now we'll add additional data collections to the BRON db, in particular, mappings from MITRE ATT&CK Techniques to NIST SP 800-53 security controls. These mapping where done by MITRE Engenuity Center for Threat-Informed Defense (see: https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings). <br />

docker-compose up <br />
This command will also create a python flask container that we'll be using as a provisional UI to test the tool. <br />
When the driver container exits, the new collections will have been added to the db. You can access the UI at localhost:5000. <br />

Go back to the SSP_Manager folder: <br />
cd .. <br />

And go into the oscal-cli-docker folder: <br />
cd oscal-cli-docker <br />
docker build -t validation . <br />
This command will create a docker image for NIST's OSCAL validation tool. When a file is submitted for validation on the UI, the flask container will spin up a container for the validation tool using this docker image. <br />


The application is now ready. Going forward, to restart the application, you only need to restart the aragodb and flask containers with: <br />
docker start containerID <br />

You can stop them with: <br />
docker stop containerID <br />

There is a Test_Files folder with three test files. <br />
profile.yaml can be used to test the validation tool. <br />
controls.json and cve.json can be used to test the security control prioritization functionality. <br />


Funding Agency:   <br />

[<img src="https://www.cisa.gov/profiles/cisad8_gov/themes/custom/gesso/dist/images/backgrounds/6fdaa25709d28dfb5cca.svg" width="20%" height="20%">](https://www.cisa.gov/)

