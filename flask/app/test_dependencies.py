from flask import Blueprint, request, jsonify, current_app as app, render_template, flash, redirect, url_for, send_from_directory
import logging
import subprocess
import os
from flask import render_template
import threading
from . import cwe_cve_to_techniques
from . import priority_controls


logging.basicConfig(level=logging.INFO)

dependencies_blueprint = Blueprint('test', __name__)

def createThread(target=None):
    x = threading.Thread(target=target)
    x.start()
    x.join()

@dependencies_blueprint.route('/dependencies', methods=['GET', 'POST'])
def dependencies():
    if 'file' not in request.files:
        logging.error("No file in test dependencies request.")
        return 'No file part', 400
    implemented_controls = request.files['file']
    logging.info(f"File sent with test dependencies request: {implemented_controls}")
    implemented_controls.save(os.path.join(app.config['UPLOAD_FOLDER'], implemented_controls.filename)) 
    with open(os.path.join(app.config['UPLOAD_FOLDER'], implemented_controls.filename), 'r') as f:
                logging.info(f.read())
    if implemented_controls.filename == '':
        logging.error("No file in test dependencies request.")
        return 'No selected file', 400
    if implemented_controls:
        try:
            # Extract entry point parameters from form
            module_name = request.form.get('module_name')
            function_name = request.form.get('function_name')
            
            # Validate entry point parameters
            if not module_name or not function_name:
                logging.error("Missing entry point parameters.")
                return jsonify(error="Module name and function name are required"), 400
            
            logging.info(f"Entry point parameters - Module: {module_name}, Function: {function_name}")
            
            subprocess.run(["python3", "./app/prepareProject.py", module_name, function_name])
            createThread(cwe_cve_to_techniques.main)
            createThread(priority_controls.main)
            #if os.path.exists('./artifacts/calledVulnerableFunctionsObjectList.txt'):
                #return render_template('vulResult.html')
            context = {
                        "Reachable_vulns": "test is finished"
                    }
            logging.info(f"Context: {context}")
        except Exception as e:
            app.logger.error(f"Error saving file: {e}")
            return 'Error saving file', 500
    return jsonify(message="Vulnerability Effectivenes Test Finished.", status=200), 200
