import os
import json
import subprocess
import logging
from flask import Blueprint, jsonify, current_app
from datetime import datetime

test_runner_bp = Blueprint('test_runner', __name__)

@test_runner_bp.route('/api/run-tests', methods=['POST'])
def run_tests():
    """
    Run InSpec tests and generate a JSON file with the results.
    """
    try:
        # Path to the InSpec tests
        inspec_dir = os.path.join(current_app.root_path, '..', 'inspec')
        
        # Path to save the test results
        results_dir = os.path.join(current_app.root_path, 'react-app', 'public', 'data')
        os.makedirs(results_dir, exist_ok=True)
        
        results_file = os.path.join(results_dir, 'test_results.json')
        
        # Run InSpec tests and capture the output
        logging.info(f"Running InSpec tests from {inspec_dir}")
        
        # Command to run InSpec tests with JSON output
        cmd = [
            'inspec', 'exec', inspec_dir,
            '--reporter', 'json',
            '-o', '/tmp/inspec_output.json'
        ]
        
        # Run the command
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False  # Don't raise exception on non-zero exit
        )
        
        # Check if the command was successful
        if process.returncode != 0 and process.returncode != 100:  # 100 is the exit code when tests fail
            logging.error(f"InSpec command failed with exit code {process.returncode}")
            logging.error(f"Error output: {process.stderr}")
            return jsonify({
                'success': False,
                'message': f"InSpec command failed with exit code {process.returncode}",
                'error': process.stderr
            }), 500
        
        # Parse the InSpec JSON output
        try:
            with open('/tmp/inspec_output.json', 'r') as f:
                inspec_output = json.load(f)
        except Exception as e:
            logging.error(f"Error parsing InSpec output: {e}")
            return jsonify({
                'success': False,
                'message': f"Error parsing InSpec output: {str(e)}"
            }), 500
        
        # Transform the InSpec output into our desired format
        test_results = []
        
        # Group controls by control ID
        controls_by_id = {}
        
        for control in inspec_output.get('controls', []):
            control_id = control.get('id', '').split('-')[0]  # Extract the base control ID
            
            if control_id not in controls_by_id:
                controls_by_id[control_id] = []
            
            controls_by_id[control_id].append(control)
        
        # Process each control group
        for control_id, controls in controls_by_id.items():
            # Determine overall status
            all_passed = all(control.get('status') == 'passed' for control in controls)
            status = 'passed' if all_passed else 'failed'
            
            # Collect test results
            test_results_for_control = []
            
            for control in controls:
                for result in control.get('results', []):
                    test_results_for_control.append({
                        'test_name': control.get('title', 'Unknown Test'),
                        'status': result.get('status', 'unknown'),
                        'message': result.get('message', '')
                    })
            
            # Add to our results
            test_results.append({
                'control_id': control_id,
                'status': status,
                'test_results': test_results_for_control
            })
        
        # Save the results to a JSON file
        with open(results_file, 'w') as f:
            json.dump(test_results, f, indent=2)
        
        return jsonify({
            'success': True,
            'message': 'Tests completed successfully',
            'results_file': results_file,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logging.exception(f"Error running tests: {e}")
        return jsonify({
            'success': False,
            'message': f"Error running tests: {str(e)}"
        }), 500
