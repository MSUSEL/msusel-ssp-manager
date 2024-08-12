from flask import Blueprint, request, current_app as app
import os
import logging
from .generateSSP import generateDocuments
import threading

logging.basicConfig(level=logging.INFO)

def createThread(target=None):
    thread = threading.Thread(target=target)
    thread.start()
    thread.join()

upload_blueprint = Blueprint('upload', __name__)

@upload_blueprint.route('/shared', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    if file:
        try:
            app.logger.info(f"Current working directory: {os.getcwd()}")
            app.logger.info(f"Saving {file.filename} to: {app.config['UPLOAD_FOLDER']}")
            upload_folder = app.config.get('UPLOAD_FOLDER', './shared/') # Default to /shared folder if UPLOAD_FOLDER is not set.
            file.save(os.path.join(upload_folder, file.filename))
            createThread(generateDocuments)
            return 'File successfully uploaded', 200
        except Exception as e:
            app.logger.error(f"Error saving file: {e}")
            return 'Error saving file', 500
