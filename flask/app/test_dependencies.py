from flask import Blueprint, request, jsonify, current_app as app
import logging
import subprocess


logging.basicConfig(level=logging.INFO)

dependencies_blueprint = Blueprint('test', __name__)

@dependencies_blueprint.route('/dependencies', methods=['GET', 'POST'])
def dependencies():
    subprocess.run(["python3", "prepareProject.py", "abstractClass", "main_function"])
    context = {
                "Reachable_vulns": "test is finished"
            }
    logging.info(f"Context: {context}")
    return jsonify(message="Vulnerability Effectivenes Test Finished.", status=200), 200