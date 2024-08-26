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
            oscal_client_arguments = f"{self.oscal_model} validate /shared/{self.oscal_file}"
            # Catch the exception if the container exits with a non-zero exit code
            try:
                self.dockerClient.containers.run("oscalprocessing", oscal_client_arguments, volumes = [f"{app.config['HOST_VOLUME_PATH']}/flask/shared:/shared"])
            except:
                print("The oscal-cli container exited with non-zero exit code.")
            self.getContainer()

        elif self.operation == "convert":
            if self.currentFormat == "json":
                self.newFormat = "yaml"
            elif self.currentFormat == "yaml":
                self.newFormat = "json"
            logging.info(f"Converting {self.oscal_file} to {self.newFormat} format.")
            oscal_client_arguments = f"{self.oscal_model} convert --to {self.newFormat} /shared/{self.oscal_file} /shared/{self.oscal_model}/{self.filename_no_extension}.{self.newFormat}"
            logging.info(f"Arguments: {oscal_client_arguments}")
            # Catch the exception if the container exits with a non-zero exit code
            try:
                self.dockerClient.containers.run("oscalprocessing", oscal_client_arguments, volumes = [f"{app.config['HOST_VOLUME_PATH']}/flask/shared:/shared"])
            except:
                print("The oscal-cli container exited with non-zero exit code.")
            self.getContainer()
        
    def getContainer(self):  
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
        self.myContainer.remove() #Remove the container from the host's docker engine


def runOSCALProcessing(oscal_file, operation, file_type):
    oscal_file.save(os.path.join(app.config['UPLOAD_FOLDER'], oscal_file.filename)) 
    oscalProcessingObject = OscalDocumentProcessing(oscal_file.filename, operation, file_type)
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
