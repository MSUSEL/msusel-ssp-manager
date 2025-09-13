from flask import Blueprint, jsonify
import json
import logging
import os

vulnerable_packages_blueprint = Blueprint('vulnerable_packages', __name__)
logging.basicConfig(level=logging.INFO)

def load_package_audit_data():
    """Load package audit data from JSON file."""
    # Get the current directory and construct path to shared folder
    cur_dir = os.path.abspath(os.path.dirname(__file__))
    # The shared folder is within the flask directory (same level as app folder)
    flask_dir = os.path.dirname(cur_dir)  # This gets us to the flask directory
    shared_dir = os.path.join(flask_dir, 'shared')
    package_audit_path = os.path.join(shared_dir, 'package_audit_report.json')
    
    logging.info(f"Loading package audit data from {package_audit_path}")
    
    try:
        with open(package_audit_path, 'r') as file:
            audit_data = json.load(file)
            logging.info(f"Successfully loaded package audit data with {len(audit_data.get('packages', []))} packages")
            return audit_data
    except FileNotFoundError:
        logging.error(f"Package audit report file not found at {package_audit_path}")
        return {
            "error": "Package audit report not found",
            "message": "The package audit report file could not be located. Please ensure the audit has been run."
        }
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing JSON from package audit report: {e}")
        return {
            "error": "Invalid JSON format",
            "message": "The package audit report file contains invalid JSON data."
        }
    except Exception as e:
        logging.error(f"Unexpected error loading package audit data: {e}")
        return {
            "error": "Unexpected error",
            "message": "An unexpected error occurred while loading the package audit report."
        }


@vulnerable_packages_blueprint.route('/package_report', methods=['GET'])
def package_report():
    """Endpoint to serve package audit report data."""
    logging.info("Package report endpoint called")
    
    # Load the package audit data
    audit_data = load_package_audit_data()
    
    # Return the data as JSON
    return jsonify(audit_data)


def main():
    """Main function for testing purposes."""
    pass


if __name__ == "__main__":
    main()
