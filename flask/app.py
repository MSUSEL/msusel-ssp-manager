import os
from flask import Flask, flash, request, redirect, url_for, render_template, send_from_directory
import cwe_cve_to_techniques
import threading
import shutil
import logging
import docker
from generate import generateDocuments
import subprocess

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')
app.config['OSCAL_FOLDER'] = os.getenv('OSCAL_FOLDER')
app.config['HOST_VOLUME_PATH'] = os.getenv('HOST_VOLUME_PATH')
app.config['TEMPLATES_AUTO_RELOAD'] = True

if not os.getenv('SECRET_KEY'):
    raise ValueError("No SECRET_KEY set for Flask application")
app.secret_key = os.getenv('SECRET_KEY')


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


def createThread(target=None):
    x = threading.Thread(target=target)
    x.start()
    x.join()

def runOSCALValidation(oscal_file, operation):
    oscal_file.save(os.path.join(app.config['OSCAL_FOLDER'], oscal_file.filename))
    oscalValidationObject = OscalDocumentProcessing(oscal_file.filename, operation)
    createThread(oscalValidationObject.runOSCALDocumentProcessingContainer())
    context = {
                "validation_output_list": oscalValidationObject.validation_output_list,
                "fileName": oscalValidationObject.oscal_file,
            }
    return context


def saveUploadedControlAndVulnerabilitiesFiles(ctrl_file, ctrl_filename, vul_file, vul_filename):
    ctrl_file.save(os.path.join(app.config['UPLOAD_FOLDER'], ctrl_filename))
    shutil.copyfile(app.config['UPLOAD_FOLDER'] + '/' + ctrl_filename, app.config['UPLOAD_FOLDER'] + '/controls.json')
    vul_file.save(os.path.join(app.config['UPLOAD_FOLDER'], vul_filename))
    shutil.copyfile(app.config['UPLOAD_FOLDER'] + '/' + vul_filename, app.config['UPLOAD_FOLDER'] + '/vulnerabilities.json')


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        try:
            oscal_doc = request.files["oscal_document"]
            operation= request.form.get("action")
            if oscal_doc.filename != '':
                context = runOSCALValidation(oscal_doc, operation)
                return render_template('validationResults.html', **context)
        except:
            logging.error("No OSCAL document submitted for validation.")

        
        # Template generation request case.
        try:
            profile = request.files["profile"]
            if profile.filename != '':
                profile.save(os.path.join(app.config['OSCAL_FOLDER'], profile.filename))
                return redirect(url_for('templateGenerated'))
        except:
            logging.error("No profile submitted for template generation.")
        
        # Security controls prioritization request case.
        ctrl_file = request.files["control_file"]
        vul_file = request.files["vul_file"]
        if ctrl_file.filename == '':
            flash('Error: Please Upload a Control File and a Vulnerability File.')
            return redirect(request.referrer) 
        elif vul_file.filename == '':
            flash('Error: Please Upload a Control File and a Vulnerability File.')
            return redirect(request.referrer)
        ctrl_filename = 'in_' + ctrl_file.filename
        vul_filename = 'in_' + vul_file.filename
        saveUploadedControlAndVulnerabilitiesFiles(ctrl_file, ctrl_filename, vul_file, vul_filename)
        
        # Security controls prioritization with tactic selection case.
        file = open(app.config['UPLOAD_FOLDER'] + '/input.txt', 'w')
        file.write('TA00' + request.form.get("tactic_id"))
        file.close()

        # Security controls prioritization case.
        return redirect(url_for('result'))
    
    # In case of a GET request
    return render_template('index.html')


@app.route('/templates/table')
def table():
    return render_template('table.html')

@app.route('/templates/vulntable')
def vulntable():
    return render_template('vulntable.html')

@app.route('/templates/network_flow')
def network_flow():
    return render_template('network_flow.html')

@app.route('/templates/result', methods=['GET', 'POST'])
def result():
    createThread(cwe_cve_to_techniques.main)
    if os.path.exists('./artifacts/calledVulnerableFunctionsObjectList.txt'):
        return render_template('vulResult.html')
    return render_template('result.html')

@app.route('/templates/templateGenerated', methods=['GET', 'POST'])
def templateGenerated():
    createThread(generateDocuments)
    return render_template('templateGenerated.html')

@app.route('/templates/graph')
def graph():
    return render_template('graph.html')

@app.route('/shared/<name>')
def download_file(name):
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)

@app.route('/vulnerability_effectiveness')
def vulnerability_effectiveness():
    subprocess.run(["python3", "prepareProject.py", "abstractClass", "main_function"])
    return render_template('vulnerability_effectiveness.html')

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=False) 
    # TODO: debug=True may incorrectlly restart the server during the vulnerability_effectiveness route