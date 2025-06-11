import os
import json
import logging
import time
import threading
from flask import Blueprint, jsonify, current_app
from datetime import datetime

test_runner_bp = Blueprint('test_runner', __name__)

def run_tests_async(app, output_file):
    """
    Run InSpec tests asynchronously in a background thread.
    This allows the API endpoint to return immediately while tests run in the background.

    Args:
        app: Flask application instance for context
        output_file: Path where processed results should be written
    """
    try:
        # Import here to avoid circular imports
        from .inspec_runner import run_inspec_container

        # Set up application context for the background thread
        with app.app_context():
            logging.info("Starting asynchronous InSpec test execution")
            success, message, exit_code = run_inspec_container(output_file)

            if success:
                logging.info(f"InSpec tests completed successfully: {message}")
            else:
                logging.error(f"InSpec tests failed: {message}")

    except Exception as e:
        logging.exception(f"Error in async test execution: {e}")

@test_runner_bp.route('/api/run-tests', methods=['POST'])
def run_tests():
    """
    Asynchronous endpoint for running InSpec tests.
    Returns immediately and runs tests in background thread.
    Frontend should poll for results using the polling mechanism.
    """
    try:
        # Determine project root - same logic as in inspec_runner
        possible_roots = [
            '/share',  # If mounted as /share
            '/workdir',  # Alternative mount point
            os.path.dirname(os.path.dirname(current_app.root_path)),  # Relative to Flask app
            '/app',  # If the whole project is mounted as /app
        ]

        project_root = None
        for root in possible_roots:
            inspec_path = os.path.join(root, 'inspec')
            if os.path.exists(inspec_path) and os.path.isfile(os.path.join(inspec_path, 'inspec.yml')):
                project_root = root
                break

        if not project_root:
            # Try to determine from current working directory
            cwd = os.getcwd()
            current_dir = cwd
            for _ in range(5):  # Check up to 5 levels up
                inspec_path = os.path.join(current_dir, 'inspec')
                if os.path.exists(inspec_path) and os.path.isfile(os.path.join(inspec_path, 'inspec.yml')):
                    project_root = current_dir
                    break
                parent_dir = os.path.dirname(current_dir)
                if parent_dir == current_dir:  # Reached root
                    break
                current_dir = parent_dir

        if not project_root:
            return jsonify({
                'success': False,
                'message': 'Could not locate project root with InSpec directory'
            }), 500

        # Determine output file path
        possible_output_dirs = [
            '/react-app/public/data',  # Docker container path
            os.path.join(current_app.root_path, '..', 'react-app', 'public', 'data'),  # Flask app relative path
            os.path.join(project_root, 'flask', 'react-app', 'public', 'data'),  # Project root relative path
            '/shared/data'  # Shared volume path
        ]

        output_dir = None
        for dir_path in possible_output_dirs:
            try:
                os.makedirs(dir_path, exist_ok=True)
                if os.path.isdir(dir_path) and os.access(dir_path, os.W_OK):
                    output_dir = dir_path
                    logging.info(f"Using output directory: {output_dir}")
                    break
            except Exception as e:
                logging.warning(f"Could not use directory {dir_path}: {e}")

        if output_dir is None:
            return jsonify({
                'success': False,
                'message': 'Could not find or create a writable output directory'
            }), 500

        output_file = os.path.join(output_dir, 'test_results.json')

        # Start tests in background thread
        logging.info("Starting InSpec tests in background thread")
        test_thread = threading.Thread(
            target=run_tests_async,
            args=(current_app._get_current_object(), output_file),
            daemon=True
        )
        test_thread.start()

        # Return immediately - frontend will poll for results
        return jsonify({
            'success': True,
            'message': 'InSpec tests started successfully. Results will be available shortly.',
            'results_file': output_file,
            'timestamp': datetime.now().isoformat(),
            'status': 'running'
        })

    except Exception as e:
        logging.exception(f"Error starting tests: {e}")
        return jsonify({
            'success': False,
            'message': f"Error starting tests: {str(e)}"
        }), 500
