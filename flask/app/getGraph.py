from flask import Blueprint, request, current_app as app, send_from_directory, jsonify, send_file
import os
import logging

logging.basicConfig(level=logging.INFO)

getGraph_blueprint = Blueprint('getGraph', __name__)

@getGraph_blueprint.route('/graph', methods=['GET','POST'])
def getGraph():
    # Define the path to the HTML file
    html_file_path = '../shared/graph.html'  # Use an absolute path or correct relative path

    try:
        # Verify that the file exists
        if not os.path.exists(html_file_path):
            logging.error(f'File not found: {html_file_path}')
            return f'Error: File not found - {html_file_path}', 404

        # Use send_file to return the HTML file
        return send_file(html_file_path, mimetype='text/html')
    except Exception as e:
        logging.error(f'Error occurred: {str(e)}')
        return str(e), 500
    

@getGraph_blueprint.route('/table', methods=['GET','POST'])
def getTable():
    # Define the path to the HTML file
    html_file_path = '../shared/table.html'  # Use an absolute path or correct relative path

    try:
        # Verify that the file exists
        if not os.path.exists(html_file_path):
            logging.error(f'File not found: {html_file_path}')
            return f'Error: File not found - {html_file_path}', 404

        # Use send_file to return the HTML file
        return send_file(html_file_path, mimetype='text/html')
    except Exception as e:
        logging.error(f'Error occurred: {str(e)}')
        return str(e), 500
    
    
@getGraph_blueprint.route('/network_flow', methods=['GET','POST'])
def getNetwork_flow():
    # Define the path to the HTML file
    html_file_path = '../shared/network_flow.html'  # Use an absolute path or correct relative path

    try:
        # Verify that the file exists
        if not os.path.exists(html_file_path):
            logging.error(f'File not found: {html_file_path}')
            return f'Error: File not found - {html_file_path}', 404

        # Use send_file to return the HTML file
        return send_file(html_file_path, mimetype='text/html')
    except Exception as e:
        logging.error(f'Error occurred: {str(e)}')
        return str(e), 500
    
    
@getGraph_blueprint.route('/vulntable', methods=['GET','POST'])
def getVulntable():
    # Define the path to the HTML file
    html_file_path = '../shared/vulntable.html'  # Use an absolute path or correct relative path

    try:
        # Verify that the file exists
        if not os.path.exists(html_file_path):
            logging.error(f'File not found: {html_file_path}')
            return f'Error: File not found - {html_file_path}', 404

        # Use send_file to return the HTML file
        return send_file(html_file_path, mimetype='text/html')
    except Exception as e:
        logging.error(f'Error occurred: {str(e)}')
        return str(e), 500