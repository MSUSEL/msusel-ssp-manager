from flask import Blueprint, request, current_app as app, send_from_directory, jsonify, send_file
import os
import logging

logging.basicConfig(level=logging.INFO)

getVulnTable_blueprint = Blueprint('getVulnTable', __name__)

@getVulnTable_blueprint.route('/vulntable', methods=['GET','POST'])
def getVulnTable():
    # Define the path to the HTML file
    html_file_path = '../shared/vulntable.html'  # Use an absolute path or correct relative path

    try:
        # Verify that the file exists
        if not os.path.exists(html_file_path):
            logging.error(f'File not found: {html_file_path}')
            return f'Error: File not found - {html_file_path}', 404

        # Use send_file to return the HTML file
        logging.info(f'Sending file: {html_file_path}')
        return send_file(html_file_path, mimetype='text/html')
    except Exception as e:
        logging.error(f'Error occurred: {str(e)}')
        return str(e), 500