import os
import json
import logging
import docker
from flask import Blueprint, jsonify, current_app
from datetime import datetime
from .inspec_processor import process_inspec_results

inspec_runner_bp = Blueprint('inspec_runner', __name__)

def run_inspec_container(output_file):
    """
    Run InSpec tests in a Docker container and process the results.
    Following the working patterns from validate.py for container-in-container execution.

    Uses HOST_UID:HOST_GID to ensure proper file ownership (avoiding root-owned files).
    This follows the same pattern as validate.py but uses UID:GID format since
    chef/inspec image may not have an 'appuser' account.

    Args:
        output_file (str): Path where processed results should be written

    Returns:
        tuple: (success: bool, message: str, exit_code: int)
    """
    try:
        # Use the working directory pattern from validate.py
        # The Flask container has access to /workdir which contains the flask/ directory
        flask_dir = "/workdir"  # This is where the Flask app runs

        # Create output directory in shared volume (following validate.py pattern)
        shared_dir = "/shared"
        temp_output_dir = os.path.join(shared_dir, "tmp_inspec_output")
        os.makedirs(temp_output_dir, exist_ok=True)
        logging.info(f"Created output directory: {temp_output_dir}")

        # Define paths - InSpec profile is now at flask/inspec
        inspec_dir = os.path.join(flask_dir, 'inspec')
        container_output_file = "/shared/tmp_inspec_output/inspec_output.json"
        host_output_file = os.path.join(temp_output_dir, 'inspec_output.json')

        # Verify InSpec directory exists
        if not os.path.exists(inspec_dir) or not os.path.isfile(os.path.join(inspec_dir, 'inspec.yml')):
            return False, f"InSpec directory not found or invalid: {inspec_dir}", 1

        logging.info(f"Running InSpec profile from {inspec_dir}")
        logging.info(f"Flask directory: {flask_dir}")
        logging.info(f"Output file: {host_output_file}")

        # Initialize Docker client (following validate.py pattern)
        client = docker.from_env()

        # Define volumes using HOST_VOLUME_PATH pattern from validate.py
        # Mount the flask directory, shared directory, and logs directory from host
        volumes = [
            f"{current_app.config['HOST_VOLUME_PATH']}/flask:/flask",
            f"{current_app.config['HOST_VOLUME_PATH']}/flask/shared:/shared",
            f"{current_app.config['HOST_VOLUME_PATH']}/logs:/logs"  # Mount logs for audit log access
        ]

        # Define the command to run inside the container
        # InSpec profile is now at /flask/inspec in the container
        command = [
            'exec', '/flask/inspec',
            '--reporter', f'json:{container_output_file}',
            '--log-level', 'debug',
            '--chef-license', 'accept'
        ]

        logging.info(f"Running InSpec container with command: {' '.join(command)}")
        logging.info(f"Volumes: {volumes}")

        # Debug: Check if directories exist and log user configuration
        logging.info(f"Flask dir exists: {os.path.exists(flask_dir)}")
        logging.info(f"Temp output dir exists: {os.path.exists(temp_output_dir)}")
        logging.info(f"InSpec profile exists: {os.path.exists(inspec_dir)}")
        logging.info(f"HOST_UID from config: {current_app.config.get('HOST_UID')}")
        logging.info(f"HOST_GID from config: {current_app.config.get('HOST_GID')}")

        # Run the container following validate.py pattern
        try:
            # Use the same user ownership pattern as validate.py for container execution
            # Get HOST_UID and HOST_GID from Flask config (set by docker-compose.yml)
            # This ensures files created by the container have correct ownership
            host_uid = current_app.config.get('HOST_UID')
            host_gid = current_app.config.get('HOST_GID')

            if host_uid and host_gid:
                # Use UID:GID format for chef/inspec container (more portable than username)
                user_spec = f"{host_uid}:{host_gid}"
                logging.info(f"Running InSpec container as user {user_spec}")
            else:
                # Fallback to appuser if HOST_UID/HOST_GID not available
                user_spec = 'appuser'
                logging.warning("HOST_UID/HOST_GID not available, falling back to appuser")

            # Connect to ssp_network so InSpec can reach mock-server
            # Run with proper user ownership to avoid root-owned files
            container = client.containers.run(
                'chef/inspec',
                command,
                volumes=volumes,
                network='ssp_network',  # Use ssp_network to reach mock-server
                user=user_spec,  # Run as HOST_UID:HOST_GID for proper file ownership
                remove=False,  # Keep container for debugging initially
                detach=False,  # Wait for completion
                stdout=True,
                stderr=True
            )

            # Container output is returned as bytes, decode it
            output = container.decode('utf-8') if isinstance(container, bytes) else str(container)
            logging.info(f"InSpec container output: {output}")

            # Since we used remove=True and detach=False, the container has completed
            exit_code = 0  # If we get here, the container ran successfully

        except docker.errors.ContainerError as e:
            # Container exited with non-zero exit code
            exit_code = e.exit_status
            output = e.stderr.decode('utf-8') if e.stderr else ''
            logging.info(f"InSpec container failed with exit code {exit_code}")
            logging.info(f"Container stderr: {output}")

            # Exit codes 0 and 100 are acceptable for InSpec (100 = test failures but command succeeded)
            if exit_code not in [0, 100]:
                return False, f"InSpec execution failed with exit code {exit_code}: {output}", exit_code

        except docker.errors.ImageNotFound as e:
            logging.error(f"InSpec Docker image not found: {e}")
            return False, f"InSpec Docker image not found: {str(e)}", 1
        except docker.errors.APIError as e:
            logging.error(f"Docker API error: {e}")
            return False, f"Docker API error: {str(e)}", 1
        except Exception as e:
            logging.error(f"Error running InSpec container: {e}")
            return False, f"Error running InSpec container: {str(e)}", 1

        logging.info(f"InSpec completed with exit code {exit_code}")
        
        # Check if output file was created
        if not os.path.exists(host_output_file):
            return False, f"InSpec output file not created: {host_output_file}", 1
        
        # Process the results
        if process_inspec_results(host_output_file, output_file):
            logging.info("Successfully processed InSpec results")
            
            # Clean up temporary directory
            try:
                import shutil
                shutil.rmtree(temp_output_dir)
                logging.info(f"Cleaned up temporary directory: {temp_output_dir}")
            except Exception as e:
                logging.warning(f"Failed to clean up temporary directory {temp_output_dir}: {e}")
            
            return True, "InSpec tests completed successfully", exit_code
        else:
            return False, "Failed to process InSpec results", 1

    except Exception as e:
        logging.error(f"Error running InSpec container: {e}")
        import traceback
        traceback.print_exc()
        return False, f"Error running InSpec container: {str(e)}", 1


# The /api/run-tests route is handled by test_runner.py
# This module only provides the run_inspec_container function
