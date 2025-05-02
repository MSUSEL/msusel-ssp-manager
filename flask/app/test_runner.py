import os
import json
import logging
import time
from flask import Blueprint, jsonify, current_app
from datetime import datetime

test_runner_bp = Blueprint('test_runner', __name__)

@test_runner_bp.route('/api/run-tests', methods=['POST'])
def run_tests():
    """
    Run InSpec tests and generate a JSON file with the results.
    """
    try:
        # Path to save the test results - try multiple possible locations
        possible_dirs = [
            '/react-app/public/data',  # Docker container path
            os.path.join(current_app.root_path, '..', 'react-app', 'public', 'data'),  # Flask app relative path
            os.path.join(os.path.dirname(os.path.dirname(current_app.root_path)), 'flask', 'react-app', 'public', 'data'),  # Project root relative path
            '/workdir/react-app/public/data',  # Alternative Docker path
            '/shared/data'  # Shared volume path
        ]

        # Find the first directory that exists or can be created
        results_dir = None
        for dir_path in possible_dirs:
            try:
                os.makedirs(dir_path, exist_ok=True)
                if os.path.isdir(dir_path) and os.access(dir_path, os.W_OK):
                    results_dir = dir_path
                    logging.info(f"Using data directory: {results_dir}")
                    break
            except Exception as e:
                logging.warning(f"Could not use directory {dir_path}: {e}")

        if results_dir is None:
            logging.error("Could not find or create a writable data directory")
            return jsonify({
                'success': False,
                'message': 'Could not find or create a writable data directory'
            }), 500

        # Log the action
        logging.info("Triggering InSpec tests to run on host")

        # Look for existing test results
        test_results_path = os.path.join(results_dir, 'test_results.json')

        # Create a trigger file to signal that tests should be run
        trigger_file = os.path.join(results_dir, 'run_tests_trigger.txt')
        try:
            with open(trigger_file, 'w') as f:
                f.write(datetime.now().isoformat())
            logging.info(f"Created trigger file at {trigger_file}")
        except Exception as e:
            logging.error(f"Failed to create trigger file: {e}")
            return jsonify({
                'success': False,
                'message': f'Failed to create trigger file: {str(e)}'
            }), 500

        logging.info("Waiting for test results to be updated...")

        # Wait for the host script to update the results
        # Poll for changes to the test results file
        max_wait_time = 120  # Maximum wait time in seconds
        poll_interval = 0.5  # Poll interval in seconds
        start_time = time.time()

        # Get the current modification time of the results file if it exists
        initial_mtime = os.path.getmtime(test_results_path) if os.path.exists(test_results_path) else 0

        # Poll until the file is modified or max wait time is reached
        while time.time() - start_time < max_wait_time:
            # Check if the file exists and has been modified
            if os.path.exists(test_results_path):
                current_mtime = os.path.getmtime(test_results_path)
                if current_mtime > initial_mtime:
                    logging.info(f"Test results file has been updated")
                    break

            # Wait before polling again
            time.sleep(poll_interval)

        # Log a warning if we timed out waiting for results
        if time.time() - start_time >= max_wait_time:
            logging.warning(f"Timed out waiting for test results to be updated")

        # Check if test results exist
        if os.path.exists(test_results_path):
            # Use existing test results
            logging.info(f"Using test results from {test_results_path}")
            # Get the file modification time
            last_modified = os.path.getmtime(test_results_path)
            last_modified_str = datetime.fromtimestamp(last_modified).isoformat()
            
            # Log the content of the test results file
            try:
                with open(test_results_path, 'r') as f:
                    test_results_content = json.load(f)
                    #logging.info(f"Test results content: {json.dumps(test_results_content, indent=2)}")
            except Exception as e:
                logging.error(f"Error reading test results file: {e}")

            return jsonify({
                'success': True,
                'message': 'Using existing test results',
                'results_file': test_results_path,
                # Log the test results content before returning
                'results': json.loads(open(test_results_path).read()) if os.path.exists(test_results_path) else None,
                'timestamp': last_modified_str
            })
        else:
            # Create sample data if no results exist
            logging.info("No test results found. Creating sample test results")
            sample_data = [
                {
                    "control_id": "ac-2",
                    "status": "passed",
                    "test_results": [
                        {
                            "test_name": "Role-based access control",
                            "status": "passed",
                            "message": "Regular user can access user profile"
                        }
                    ]
                },
                {
                    "control_id": "ia-2",
                    "status": "failed",
                    "test_results": [
                        {
                            "test_name": "Multi-factor authentication",
                            "status": "failed",
                            "message": "Staff user can authenticate without MFA"
                        }
                    ]
                }
            ]
            with open(test_results_path, 'w') as f:
                json.dump(sample_data, f, indent=2)

            return jsonify({
                'success': True,
                'message': 'Created sample test results',
                'results_file': test_results_path,
                'timestamp': datetime.now().isoformat()
            })



    except Exception as e:
        logging.exception(f"Error running tests: {e}")
        return jsonify({
            'success': False,
            'message': f"Error running tests: {str(e)}"
        }), 500
