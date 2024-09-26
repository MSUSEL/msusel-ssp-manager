from flask import Blueprint, request, send_file, make_response
import os
import logging

logging.basicConfig(level=logging.INFO)

getGraph_blueprint = Blueprint('getGraph', __name__)

@getGraph_blueprint.route('/graph', methods=['GET', 'POST'])
def getGraph():
    # Define the path to the HTML file
    html_file_path = '../shared/graph.html'  # Use an absolute path or correct relative path

    try:
        # Verify that the file exists
        if not os.path.exists(html_file_path):
            logging.error(f'File not found: {html_file_path}')
            return f'Error: File not found - {html_file_path}', 404

        # Send the file using send_file, with cache-control headers
        response = make_response(send_file(html_file_path, mimetype='text/html'))

        # Add cache-control headers to prevent caching
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

        return response

    except Exception as e:
        logging.error(f'Error occurred: {str(e)}')
        return str(e), 500
