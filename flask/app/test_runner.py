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
    Legacy endpoint that redirects to the new InSpec runner.
    This maintains backward compatibility with the existing UI.
    """
    try:
        # Import here to avoid circular imports
        from .inspec_runner import run_inspec_container

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

        # Run InSpec tests using the new simplified function
        logging.info("Running InSpec tests directly via container")
        success, message, exit_code = run_inspec_container(output_file)

        if success:
            # Read the results to include in response
            try:
                with open(output_file, 'r') as f:
                    results_data = json.load(f)

                return jsonify({
                    'success': True,
                    'message': message,
                    'results_file': output_file,
                    'results': results_data.get('results', []) if isinstance(results_data, dict) else results_data,
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                logging.warning(f"Could not read results file: {e}")
                return jsonify({
                    'success': True,
                    'message': f"{message} (Warning: Could not read results file)",
                    'results_file': output_file,
                    'timestamp': datetime.now().isoformat()
                })
        else:
            return jsonify({
                'success': False,
                'message': message
            }), 500

    except Exception as e:
        logging.exception(f"Error running tests: {e}")
        return jsonify({
            'success': False,
            'message': f"Error running tests: {str(e)}"
        }), 500
