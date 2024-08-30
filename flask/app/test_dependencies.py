from flask import Blueprint, request, current_app as app
import os
import logging
import threading
import subprocess

logging.basicConfig(level=logging.INFO)

def createThread(target=None):
    thread = threading.Thread(target=target)
    thread.start()
    thread.join()

dependencies_blueprint = Blueprint('test', __name__)

@dependencies_blueprint.route('/dependencies', methods=['GET', 'POST'])
def dependencies():
    subprocess.run(["python3", "prepareProject.py", "abstractClass", "main_function"])
    context = {
                "Reachable vulns": "test is finished"
            }
    logging.info(f"Context: {context}")
    return context