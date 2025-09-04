from flask import Blueprint, request, jsonify
import os
import json
import logging
import re
from .db_queries import DatabaseConnection, DatabaseQueryService
from .manageData import ManageData
from .tacticsAndTecniquesGraph import convert_nx_to_vis_format, convert2visNetworkFormat

logging.basicConfig(level=logging.INFO)

# Create the blueprint for CVE/CWE mappings
cve_cwe_mappings_blueprint = Blueprint('cve_cwe_mappings', __name__)

def validate_cve_cwe_format(data):
    """
    Validate the format of uploaded CVE/CWE data.
    Returns tuple: (is_valid, data_type, error_message)
    """
    try:
        # Check if data is a list
        if not isinstance(data, list):
            return False, None, "Data must be an array of objects"

        # Check if list is not empty
        if len(data) == 0:
            return False, None, "Data array cannot be empty"

        # Check if all items are dictionaries
        if not all(isinstance(item, dict) for item in data):
            return False, None, "All items must be objects"

        # Detect format by checking first item
        first_item = data[0]

        # Check for CVE format
        if 'cve' in first_item:
            # Validate CVE pattern (CVE-YYYY-NNNN)
            cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
            for item in data:
                if 'cve' not in item:
                    return False, None, "All items must have 'cve' key for CVE format"
                if not cve_pattern.match(item['cve']):
                    return False, None, f"Invalid CVE format: {item['cve']}. Expected format: CVE-YYYY-NNNN"
            return True, 'cve', None

        # Check for CWE format
        elif 'cwe' in first_item:
            # Validate CWE numeric format
            for item in data:
                if 'cwe' not in item:
                    return False, None, "All items must have 'cwe' key for CWE format"
                try:
                    # CWE should be numeric (can be string or int)
                    int(str(item['cwe']))
                except ValueError:
                    return False, None, f"Invalid CWE format: {item['cwe']}. Expected numeric value"
            return True, 'cwe', None

        else:
            return False, None, "Data must contain either 'cve' or 'cwe' keys"

    except Exception as e:
        return False, None, f"Validation error: {str(e)}"

@cve_cwe_mappings_blueprint.route('/upload', methods=['POST'])
def upload_cve_cwe_file():
    """
    Handle CVE/CWE file upload and processing.
    Accepts JSON files containing either CVE or CWE lists.
    """
    try:
        # Check if file is present in request
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in request'}), 400

        file = request.files['file']

        # Check if file was selected
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        # Basic file validation - check if file exists and is not empty
        if not file:
            return jsonify({'error': 'Invalid file'}), 400

        # Parse JSON content
        try:
            file_content = file.read().decode('utf-8')
            data = json.loads(file_content)
        except json.JSONDecodeError as e:
            return jsonify({'error': f'Invalid JSON format: {str(e)}'}), 400
        except UnicodeDecodeError:
            return jsonify({'error': 'File must be UTF-8 encoded'}), 400

        # Validate file format
        is_valid, data_type, error_message = validate_cve_cwe_format(data)
        if not is_valid:
            return jsonify({'error': error_message}), 400

        # File format validation successful
        logging.info(f"File upload received and validated: {file.filename}, type: {data_type}, items: {len(data)}")

        # Save uploaded file to shared directory
        vulnerabilities_path = '/shared/vulnerabilities.json'
        controls_path = '/shared/controls.json'

        try:
            # Save uploaded data to vulnerabilities.json (overwriting existing)
            with open(vulnerabilities_path, 'w') as f:
                json.dump(data, f)
            logging.info(f"Saved uploaded data to {vulnerabilities_path}")

            # Create empty controls.json file
            empty_controls = []
            with open(controls_path, 'w') as f:
                json.dump(empty_controls, f)
            logging.info(f"Created empty controls file at {controls_path}")

        except IOError as e:
            logging.error(f"Error writing files: {e}")
            return jsonify({'error': 'Failed to save uploaded data'}), 500

        # Initialize database connection and query service
        try:
            cur_dir = os.getcwd()
            db_connection = DatabaseConnection()
            query_service = DatabaseQueryService(db_connection)

            # Create ManageData instance to process uploaded CVE/CWE data
            logging.info("Initializing ManageData for CVE/CWE processing...")
            data_manager = ManageData(cur_dir, query_service)
            logging.info("ManageData processing completed successfully")

            # Extract graph data and recommendations from ManageData
            response_data = {
                'message': 'CVE/CWE data processed successfully',
                'filename': file.filename,
                'data_type': data_type,
                'item_count': len(data),
                'processing_status': 'completed'
            }

            # Add graph data if available
            if hasattr(data_manager, 'tacticsAndTechniquesGraph') and data_manager.tacticsAndTechniquesGraph:
                # Convert NetworkX graph to JSON-serializable format
                graph_data = convert_nx_to_vis_format(data_manager.tacticsAndTechniquesGraph)
                response_data['graph_data'] = convert2visNetworkFormat(graph_data)
                logging.info("Added tactics and techniques graph data to response")

            # Add priority controls table data if available
            if hasattr(data_manager, 'json_priority_controls_table_data') and data_manager.json_priority_controls_table_data:
                response_data['priority_controls'] = data_manager.json_priority_controls_table_data
                logging.info("Added priority controls data to response")

            # Add attack paths data if available
            if hasattr(data_manager, 'attack_paths_graph') and data_manager.attack_paths_graph:
                # Convert attack paths graph to JSON-serializable format
                attack_paths_data = convert_nx_to_vis_format(data_manager.attack_paths_graph)
                response_data['attack_paths'] = convert2visNetworkFormat(attack_paths_data)
                logging.info("Added attack paths data to response")

            # Handle empty results gracefully
            if not any([
                response_data.get('graph_data'),
                response_data.get('priority_controls'),
                response_data.get('attack_paths')
            ]):
                response_data['warning'] = 'No mappings found for the provided CVE/CWE data'
                logging.warning("No graph data or recommendations generated from uploaded CVE/CWE data")

            return jsonify(response_data), 200

        except Exception as e:
            logging.error(f"Error during ManageData processing: {e}")
            return jsonify({'error': 'Failed to process CVE/CWE data through database'}), 500

    except Exception as e:
        logging.error(f"Error in CVE/CWE upload: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500
