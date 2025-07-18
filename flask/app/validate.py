from flask import Blueprint, request, current_app as app, jsonify
import os
import logging
import threading
import docker
import uuid
import json
from werkzeug.utils import secure_filename

logging.basicConfig(level=logging.INFO)

# Global dictionary for storing validation job status and results
# Job structure: {job_id: {"status": "PENDING|RUNNING|COMPLETED|FAILED", "result": None|result_data}}
validation_jobs = {}

def run_validation_async(app, job_id, file_path, file_type, operation):
    """
    Run OSCAL validation asynchronously in a background thread.
    This allows the API endpoint to return immediately while validation runs in the background.
    Based on run_tests_async() pattern from test_runner.py.

    Args:
        app: Flask application instance for context
        job_id: Unique identifier for this validation job
        file_path: Path to the uploaded file to validate
        file_type: Type of OSCAL document (catalog, profile, ssp, etc.)
        operation: Operation to perform (validate, convert, etc.)
    """
    try:
        # Set up application context for the background thread
        with app.app_context():
            logging.info(f"Starting asynchronous OSCAL validation for job {job_id}")

            # Step 2.2.1: Update job status to "RUNNING" before processing
            if job_id in validation_jobs:
                validation_jobs[job_id]["status"] = "RUNNING"
                logging.info(f"Job {job_id} status updated to RUNNING")
            else:
                logging.error(f"Job {job_id} not found in validation_jobs when updating to RUNNING")
                return

            # Step 2.2.2: Call existing oscalProcessingObject.runOSCALDocumentProcessingContainer() directly
            # Extract filename from file_path for the processing object
            filename = os.path.basename(file_path)
            oscal_processing_object = OscalDocumentProcessing(filename, operation, file_type)

            # Run the validation container directly (this is the long-running operation)
            # Note: We call the container method directly instead of using createThread
            # to avoid the blocking thread.join() call
            logging.info(f"Calling runOSCALDocumentProcessingContainer() directly for job {job_id}")
            oscal_processing_object.runOSCALDocumentProcessingContainer()

            # Step 2.2.3: Update job status to "COMPLETED" with results on success
            # Format result to match expected structure
            formatted_result = {
                "oscal_processing_output_list": oscal_processing_object.oscal_processing_output_list,
                "fileName": oscal_processing_object.oscal_file,
            }

            # Update job status to COMPLETED with results
            if job_id in validation_jobs:
                validation_jobs[job_id]["status"] = "COMPLETED"
                validation_jobs[job_id]["result"] = formatted_result
                logging.info(f"Job {job_id} completed successfully with {len(oscal_processing_object.oscal_processing_output_list)} output lines")
            else:
                logging.error(f"Job {job_id} not found in validation_jobs when updating to COMPLETED")

    except Exception as e:
        logging.exception(f"Error in async validation for job {job_id}: {e}")

        # Step 2.2.4: Update job status to "FAILED" with error message on failure
        if job_id in validation_jobs:
            validation_jobs[job_id]["status"] = "FAILED"
            validation_jobs[job_id]["result"] = {
                "error": str(e),
                "message": f"Validation failed: {str(e)}"
            }
            logging.error(f"Job {job_id} failed with error: {str(e)}")
        else:
            logging.error(f"Job {job_id} not found in validation_jobs when updating to FAILED")

def test_async_validation():
    """
    Test function to verify the async validation setup is working.
    This can be called to test job creation and status updates.
    """
    # Create a test job
    test_job_id = str(uuid.uuid4())
    validation_jobs[test_job_id] = {
        "status": "PENDING",
        "result": None
    }

    logging.info(f"Created test job {test_job_id}")
    logging.info(f"Current validation_jobs: {validation_jobs}")

    # Test status update
    validation_jobs[test_job_id]["status"] = "RUNNING"
    logging.info(f"Updated job {test_job_id} to RUNNING")

    # Test completion
    validation_jobs[test_job_id]["status"] = "COMPLETED"
    validation_jobs[test_job_id]["result"] = {"test": "success", "message": "Test validation completed"}
    logging.info(f"Updated job {test_job_id} to COMPLETED")

    return test_job_id

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
            oscal_client_arguments = f"validate /shared/{self.oscal_file}"
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
            oscal_client_arguments = f"convert --to {self.newFormat} /shared/{self.oscal_file} /temp_{self.oscal_model}/{self.filename_no_extension}.{self.newFormat}"
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

                # Generate unique job ID
                job_id = str(uuid.uuid4())
                logging.info(f"Generated job ID: {job_id}")

                # Save file to upload folder
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], oscal_doc.filename)
                oscal_doc.save(file_path)
                logging.info(f"File saved to: {file_path}")

                # Create job entry with PENDING status
                validation_jobs[job_id] = {
                    "status": "PENDING",
                    "result": None
                }
                logging.info(f"Created validation job {job_id} with PENDING status")

                # Start background thread (like test_runner.py pattern)
                validation_thread = threading.Thread(
                    target=run_validation_async,
                    args=(app._get_current_object(), job_id, file_path, file_type, operation),
                    daemon=True
                )
                validation_thread.start()
                logging.info(f"Started background validation thread for job {job_id}")

                # Return job_id immediately (no waiting)
                return jsonify({"job_id": job_id}), 200

            elif operation == 'convert':
                app.logger.info(f"Convert Route. Current working directory: {os.getcwd()}")
                app.logger.info(f"Saving {oscal_doc.filename} to: {app.config['UPLOAD_FOLDER']}")
                context = runOSCALProcessing(oscal_doc, operation, file_type)
                logging.info(f"Conversion output: {context['oscal_processing_output_list']}")
                return context, 200
        except Exception as e:
            app.logger.error(f"Error saving file: {e}")
            return 'Error saving file', 500

@validate_blueprint.route('/test-async-validation', methods=['GET'])
def test_async_validation_endpoint():
    """
    Test endpoint to verify async validation setup is working.
    This tests job creation, status updates, and the global validation_jobs dictionary.
    """
    try:
        # Run the test function
        test_job_id = test_async_validation()

        # Return the current state of validation_jobs for verification
        return jsonify({
            "success": True,
            "message": "Async validation test completed",
            "test_job_id": test_job_id,
            "validation_jobs": validation_jobs,
            "job_count": len(validation_jobs)
        }), 200

    except Exception as e:
        logging.error(f"Error in test endpoint: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "validation_jobs": validation_jobs
        }), 500

@validate_blueprint.route('/status/<job_id>', methods=['GET'])
def get_validation_status(job_id):
    """
    Get the status and results of a validation job.
    Based on error handling patterns from test_runner.py.

    Args:
        job_id: UUID string identifying the validation job

    Returns:
        JSON response with job status and results (if complete)
    """
    try:
        # Validate job_id format (basic UUID check)
        if not job_id or len(job_id) != 36:
            return jsonify({
                "success": False,
                "error": "Invalid job ID format",
                "status": "ERROR"
            }), 400

        # Check if job exists
        if job_id not in validation_jobs:
            return jsonify({
                "success": False,
                "error": f"Job {job_id} not found",
                "status": "NOT_FOUND"
            }), 404

        # Get job data
        job_data = validation_jobs[job_id]
        job_status = job_data.get("status", "UNKNOWN")
        job_result = job_data.get("result", None)

        # Prepare response based on job status
        response_data = {
            "success": True,
            "job_id": job_id,
            "status": job_status
        }

        # Include results if job is complete
        if job_status == "COMPLETED" and job_result is not None:
            response_data["result"] = job_result
            logging.info(f"Returning completed results for job {job_id}")
        elif job_status == "FAILED" and job_result is not None:
            response_data["error"] = job_result
            logging.info(f"Returning error results for job {job_id}")
        else:
            # Job is still PENDING or RUNNING
            response_data["message"] = f"Job is {job_status.lower()}"
            logging.info(f"Job {job_id} is still {job_status}")

        return jsonify(response_data), 200

    except Exception as e:
        logging.exception(f"Error getting status for job {job_id}: {e}")
        return jsonify({
            "success": False,
            "error": f"Internal server error: {str(e)}",
            "status": "ERROR"
        }), 500

@validate_blueprint.route('/validation-jobs', methods=['GET'])
def get_validation_jobs():
    """
    Endpoint to view current validation jobs (for debugging/testing).
    """
    return jsonify({
        "validation_jobs": validation_jobs,
        "job_count": len(validation_jobs)
    }), 200
