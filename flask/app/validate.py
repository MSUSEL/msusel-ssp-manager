from flask import Blueprint, request, current_app as app
import os
import logging
import threading
import docker

logging.basicConfig(level=logging.INFO)

def createThread(target=None):
    thread = threading.Thread(target=target)
    thread.start()
    thread.join()

validate_blueprint = Blueprint('validate', __name__)


class OscalDocumentProcessing:
    def __init__(self, oscal_file, operation, file_type):
        self.oscal_file = oscal_file
        logging.info(f"OscalDocumentProcessing object created. File: {self.oscal_file}")
        self.filename_no_extension = self.oscal_file[:-5] # save the filename without the extension
        self.operation = operation
        self.currentFormat = self.oscal_file[-4:] # save the file extension
        self.newFormat = None
        self.oscal_processing_output_list = []
        self.dockerClient = docker.from_env() # create a client that can talk to the host's docker daemon
        self.oscal_model = file_type
        self.myContainer = None
        self.oscalProcessingContainerLogs = None

    # This entire function is run in a separate thread. A Docker container is created from 
    # the oscalprocessing image (built locally). We pass arguments to the container about
    # to be created.
    def runOSCALDocumentProcessingContainer(self):
        if self.operation == "validate":
            # The container will read the file from the host side, I think.
            oscal_client_arguments = f"{self.oscal_model} validate /shared/{self.oscal_file}"
            logging.info(f"Validation arguments: {oscal_client_arguments}")
            # Catch the exception if the container exits with a non-zero exit code
            try:
                # Use alternative methods to get user information
                current_user = os.environ.get("USER", "appuser")  # Default to 'appuser' if USER env var is not set
                logging.info(f"Current User: {current_user}")
                logging.info(f"Current working directory: {os.getcwd()}")
                try:
                    self.dockerClient.containers.run(
                        "oscalprocessing",
                        oscal_client_arguments,
                        volumes=[f"{app.config['HOST_VOLUME_PATH']}/flask/shared:/shared"]
                    )
                except docker.errors.ContainerError as e:
                    app.logger.error(f"Container error: {e}")
                except docker.errors.ImageNotFound as e:
                    app.logger.error(f"Image not found: {e}")
                except docker.errors.APIError as e:
                    app.logger.error(f"Docker API error: {e}")
                except Exception as e:
                    app.logger.error(f"An unexpected error occurred: {e}")

                logging.info("Container ran.")
            except:
                print("The oscal-cli container exited with non-zero exit code.")
            self.getContainer()

        elif self.operation == "convert":
            if self.currentFormat == "json":
                self.newFormat = "yaml"
            elif self.currentFormat == "yaml":
                self.newFormat = "json"
            logging.info(f"Converting {self.oscal_file} to {self.newFormat} format.")
            oscal_client_arguments = f"{self.oscal_model} convert --to {self.newFormat} /shared/{self.oscal_file} /temp_{self.oscal_model}/{self.filename_no_extension}.{self.newFormat}"
            logging.info(f"Arguments: {oscal_client_arguments}")
            # Catch the exception if the container exits with a non-zero exit code
            try:
                self.dockerClient.containers.run("oscalprocessing", oscal_client_arguments, volumes = [f"{app.config['HOST_VOLUME_PATH']}/flask/shared:/shared", f"{app.config['HOST_VOLUME_PATH']}/flask/temp_{self.oscal_model}:/temp_{self.oscal_model}"], user = 'appuser') # Uses the volumes to read the argument file and to wr
            except:
                print("The oscal-cli container exited with non-zero exit code.")
            self.getContainer()
        
    def getContainer(self):  
        logging.info("Getting the container logs.")
        containerList = self.dockerClient.containers.list(limit = 1) # Get the last container created by the host's docker engine
        strList = str(containerList) # Ex: [<Container: f0ff86794ced>], where the value is the container ID
        temp = strList.split(":")
        containerId = temp[1][1:11]
        self.myContainer = self.dockerClient.containers.get(containerId)
        self.getContainerLogs()

    def getContainerLogs(self):
        bytesLogOutput = self.myContainer.logs()
        self.oscalProcessingContainerLogs = bytesLogOutput.decode()
        self.createOutputList()

    def createOutputList(self):
        if self.operation == "validate":
            with open("/shared/validation.txt", "w") as f:
                    f.write(self.oscalProcessingContainerLogs)
            f.close()
            f = open('/shared/validation.txt', 'r')
            for line in f:
                self.oscal_processing_output_list.append(line)
            f.close()
        elif self.operation == "convert":
            with open("/shared/convert.txt", "w") as f:
                f.write(self.oscalProcessingContainerLogs)
            f.close()
            f = open('/shared/convert.txt', 'r') 
            for line in f:
                self.oscal_processing_output_list.append(line)
            f.close()
        logging.info(f"Output list created. Will remove processing container.")
        logging.info("Container id: " + self.myContainer.id)
        #self.myContainer.stop() #Stop the container
        self.myContainer.remove() #Remove the container from the host's docker engine


def runOSCALProcessing(oscal_file, operation, file_type):
    oscal_file.save(os.path.join(app.config['UPLOAD_FOLDER'], oscal_file.filename)) 
    logging.info(f"File saved to: {os.path.join(app.config['UPLOAD_FOLDER'], oscal_file.filename)}")
    oscalProcessingObject = OscalDocumentProcessing(oscal_file.filename, operation, file_type)
    logging.info(f"Processing object created. File saved: {oscalProcessingObject.oscal_file}. Will start thread.")
    createThread(oscalProcessingObject.runOSCALDocumentProcessingContainer())
    context = {
                "oscal_processing_output_list": oscalProcessingObject.oscal_processing_output_list,
                "fileName": oscalProcessingObject.oscal_file,
            }
    logging.info(f"Context: {context}")
    return context



@validate_blueprint.route('/shared', methods=['POST'])
def validate():
    if 'file' not in request.files:
        return 'No file part', 400
    oscal_doc = request.files['file']
    file_type = request.form.get('fileType')
    operation = request.form.get('operation')
    if oscal_doc.filename == '':
        return 'No selected file', 400
    if oscal_doc:
        try:
            if operation == 'validate':
                app.logger.info(f"Validate Route. Current working directory: {os.getcwd()}")
                app.logger.info(f"Saving {oscal_doc.filename} to: {app.config['UPLOAD_FOLDER']}")
                context = runOSCALProcessing(oscal_doc, operation, file_type)
                logging.info(f"Validation output: {context['oscal_processing_output_list']}")
                return context, 200
            elif operation == 'convert':
                app.logger.info(f"Convert Route. Current working directory: {os.getcwd()}")
                app.logger.info(f"Saving {oscal_doc.filename} to: {app.config['UPLOAD_FOLDER']}")
                context = runOSCALProcessing(oscal_doc, operation, file_type)
                logging.info(f"Conversion output: {context['oscal_processing_output_list']}")
                return context, 200
        except Exception as e:
            app.logger.error(f"Error saving file: {e}")
            return 'Error saving file', 500
