from flask import Blueprint, request, current_app as app
import os
import logging
#from .generateSSP import generateDocuments
import threading
import docker

logging.basicConfig(level=logging.INFO)

def createThread(target=None):
    thread = threading.Thread(target=target)
    thread.start()
    thread.join()

validate_blueprint = Blueprint('validate', __name__)


class OscalDocumentProcessing:
    def __init__(self, oscal_file, operation):
        self.oscal_file = oscal_file
        self.operation = operation
        self.currentFormat = self.oscal_file[-4:] # save the file extension
        self.newFormat = None
        self.validation_output_list = []
        self.dockerClient = docker.from_env() # create a client that can talk to the host's docker daemon
        self.oscal_model = self.oscal_file[:-5] # take out extension to insert model as argument
        self.myContainer = None
        self.validationContainerLogs = None

    # This entire function is run in a separate thread. A Docker container is created from 
    # the oscalprocessing image (built locally). We pass arguments to the container about
    # to be created.
    def runOSCALDocumentProcessingContainer(self):
        if self.operation == "validate":
            oscal_client_arguments = f"{self.oscal_model} validate /shared/{self.oscal_file}"
            # Catch the exception if the container exits with a non-zero exit code
            try:
                self.dockerClient.containers.run("oscalprocessing", oscal_client_arguments, volumes = [f"{app.config['HOST_VOLUME_PATH']}/flask/shared:/shared"])
            except:
                print("The oscal-cli container exited with non-zero exit code.")
            self.getContainer()

        elif self.operation == "convert":
            logging.info(f"Converting {self.oscal_file} to {self.newFormat} format.")
            if self.currentFormat == "json":
                self.newFormat = "yaml"
            elif self.currentFormat == "yaml":
                self.newFormat = "json"
            oscal_client_arguments = f"{self.oscal_model} convert --to {self.newFormat} /shared/{self.oscal_file} /shared/{self.oscal_model}.{self.newFormat}"
            # Catch the exception if the container exits with a non-zero exit code
            try:
                self.dockerClient.containers.run("oscalprocessing", oscal_client_arguments, volumes = [f"{app.config['HOST_VOLUME_PATH']}/flask/shared:/shared"])
            except:
                print("The oscal-cli container exited with non-zero exit code.")
        
    def getContainer(self):  
        containerList = self.dockerClient.containers.list(limit = 1) # Get the last container created by the host's docker engine
        strList = str(containerList) # Ex: [<Container: f0ff86794ced>], where the value is the container ID
        temp = strList.split(":")
        containerId = temp[1][1:11]
        self.myContainer = self.dockerClient.containers.get(containerId)
        self.getContainerLogs()

    def getContainerLogs(self):
        bytesLogOutput = self.myContainer.logs()
        self.validationContainerLogs = bytesLogOutput.decode()
        self.createValidationOutputList()

    def createValidationOutputList(self):
        with open("/shared/validation.txt", "w") as f:
                f.write(self.validationContainerLogs)
        f.close()
        f = open('/shared/validation.txt', 'r')
        for line in f:
            self.validation_output_list.append(line)
        f.close()
        self.myContainer.remove() #Remove the container from the host's docker engine


def runOSCALValidation(oscal_file, operation):
    oscal_file.save(os.path.join(app.config['OSCAL_FOLDER'], oscal_file.filename))
    oscalValidationObject = OscalDocumentProcessing(oscal_file.filename, operation)
    createThread(oscalValidationObject.runOSCALDocumentProcessingContainer())
    context = {
                "validation_output_list": oscalValidationObject.validation_output_list,
                "fileName": oscalValidationObject.oscal_file,
            }
    return context



@validate_blueprint.route('/shared', methods=['POST'])
def validate():
    if 'file' not in request.files:
        return 'No file part', 400
    oscal_doc = request.files['file']
    operation = 'validate'
    if oscal_doc.filename == '':
        return 'No selected file', 400
    if oscal_doc:
        try:
            app.logger.info(f"Validate Route. Current working directory: {os.getcwd()}")
            app.logger.info(f"Saving {oscal_doc.filename} to: {app.config['UPLOAD_FOLDER']}")
            #upload_folder = app.config.get('UPLOAD_FOLDER', './shared/') # Default to /shared folder if UPLOAD_FOLDER is not set.
            #oscal_doc.save(os.path.join(upload_folder, oscal_doc.filename))
            #createThread(generateDocuments)
            context = runOSCALValidation(oscal_doc, operation)
            logging.info(f"Validation output: {context['validation_output_list']}")
            return 'File successfully uploaded', 200
        except Exception as e:
            app.logger.error(f"Error saving file: {e}")
            return 'Error saving file', 500
