from flask import Blueprint, request, jsonify, current_app as app, render_template, flash, redirect, url_for, send_from_directory
import logging
import subprocess
import os
from flask import render_template
import threading
import shutil
from werkzeug.utils import secure_filename
from . import cwe_cve_to_techniques
from . import priority_controls


logging.basicConfig(level=logging.INFO)

dependencies_blueprint = Blueprint('test', __name__)

def createThread(target=None):
    x = threading.Thread(target=target)
    x.start()
    x.join()


def clear_dependencies_directory():
    """
    Safely clear the contents of the dependencies directory while preserving essential system files.
    This ensures a clean state for each new project upload.
    """
    try:
        dependencies_dir = os.path.join(os.getcwd(), "app", "dependencies")
        logging.info(f"Clearing dependencies directory: {dependencies_dir}")

        if not os.path.exists(dependencies_dir):
            logging.info("Dependencies directory does not exist, creating it")
            os.makedirs(dependencies_dir, exist_ok=True)
            return True

        # Files and directories to preserve (system files that should not be deleted)
        preserve_files = {
            'ImplementFolderUploadPlan.txt',  # Implementation documentation
            'dynamicCallGraph.py'  # May be copied here by profilerWrapper
        }

        # Get list of all items in dependencies directory
        items_to_remove = []
        for item in os.listdir(dependencies_dir):
            if item not in preserve_files and not item.startswith('.'):
                items_to_remove.append(item)

        # Remove each item
        removed_count = 0
        for item in items_to_remove:
            item_path = os.path.join(dependencies_dir, item)
            try:
                if os.path.isfile(item_path):
                    os.remove(item_path)
                    logging.info(f"Removed file: {item_path}")
                    removed_count += 1
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                    logging.info(f"Removed directory: {item_path}")
                    removed_count += 1
            except Exception as e:
                logging.error(f"Error removing {item_path}: {e}")
                # Continue with other items even if one fails
                continue

        logging.info(f"Successfully cleared {removed_count} items from dependencies directory")
        return True

    except Exception as e:
        logging.error(f"Error clearing dependencies directory: {e}")
        return False

def find_and_copy_requirements_file(dependencies_dir, uploaded_files):
    """
    Find requirements.txt in the uploaded project structure and copy it to the root of dependencies directory.
    This ensures prepareProject.py can find requirements.txt at the expected location while preserving
    the original project structure for dynamic analysis.
    
    :param dependencies_dir: Path to the dependencies directory
    :param uploaded_files: List of dictionaries with file information from upload
    :return: Boolean indicating success/failure
    """
    try:
        requirements_source_path = None
        
        # Search through uploaded files to find requirements.txt
        for file_info in uploaded_files:
            relative_path = file_info['relative_target']
            if relative_path.endswith('requirements.txt'):
                requirements_source_path = file_info['target_path']
                logging.info(f"Found requirements.txt at: {relative_path}")
                break
        
        if not requirements_source_path:
            logging.error("No requirements.txt found in uploaded files")
            return False
        
        # Define the target path where prepareProject.py expects requirements.txt
        requirements_target_path = os.path.join(dependencies_dir, 'requirements.txt')
        
        # Copy requirements.txt to the root of dependencies directory
        shutil.copy2(requirements_source_path, requirements_target_path)
        logging.info(f"✓ Copied requirements.txt from {requirements_source_path} to {requirements_target_path}")
        
        # Verify the copy was successful
        if os.path.exists(requirements_target_path):
            logging.info("✓ Verified requirements.txt exists at expected location for prepareProject.py")
            return True
        else:
            logging.error("❌ Failed to verify requirements.txt copy")
            return False
            
    except Exception as e:
        logging.error(f"Error copying requirements.txt: {e}")
        return False

def validate_project_structure(files):
    """
    Validate the uploaded project structure and check for requirements.txt.
    
    :param files: List of uploaded files from request.files.getlist('files')
    :return: Dictionary with validation results
    """
    try:
        if not files or len(files) == 0:
            return {
                'is_valid': False,
                'error': 'No files selected',
                'requirements_found': False,
                'requirements_path': None
            }
        
        # Check for reasonable file count (prevent accidental large uploads)
        if len(files) > 1000:
            return {
                'is_valid': False,
                'error': f'Too many files ({len(files)}). Maximum 1000 files allowed.',
                'requirements_found': False,
                'requirements_path': None
            }
        
        # Search for requirements.txt anywhere in the uploaded structure
        requirements_found = False
        requirements_path = None
        
        for file in files:
            if file.filename == '':
                continue
                
            relative_path = file.filename
            
            # Check if this file is requirements.txt (anywhere in the structure)
            if relative_path.endswith('requirements.txt'):
                requirements_found = True
                requirements_path = relative_path
                logging.info(f"Found requirements.txt at: {relative_path}")
                break
        
        if not requirements_found:
            return {
                'is_valid': False,
                'error': 'requirements.txt not found in uploaded project',
                'requirements_found': False,
                'requirements_path': None
            }
        
        return {
            'is_valid': True,
            'error': None,
            'requirements_found': True,
            'requirements_path': requirements_path
        }
        
    except Exception as e:
        logging.error(f"Error validating project structure: {e}")
        return {
            'is_valid': False,
            'error': f'Validation error: {str(e)}',
            'requirements_found': False,
            'requirements_path': None
        }

@dependencies_blueprint.route('/dependencies', methods=['GET', 'POST'])
def dependencies():
    if 'file' not in request.files:
        logging.error("No file in test dependencies request.")
        return 'No file part', 400
    implemented_controls = request.files['file']
    logging.info(f"File sent with test dependencies request: {implemented_controls}")
    implemented_controls.save(os.path.join(app.config['UPLOAD_FOLDER'], implemented_controls.filename)) 
    with open(os.path.join(app.config['UPLOAD_FOLDER'], implemented_controls.filename), 'r') as f:
                logging.info(f.read())
    if implemented_controls.filename == '':
        logging.error("No file in test dependencies request.")
        return 'No selected file', 400
    if implemented_controls:
        try:
            # Extract entry point parameters from form
            module_name = request.form.get('module_name')
            function_name = request.form.get('function_name')
            
            # Validate entry point parameters
            if not module_name or not function_name:
                logging.error("Missing entry point parameters.")
                return jsonify(error="Module name and function name are required"), 400
            
            logging.info(f"Entry point parameters - Module: {module_name}, Function: {function_name}")
            
            subprocess.run(["python3", "./app/prepareProject.py", module_name, function_name])
            createThread(cwe_cve_to_techniques.main)
            createThread(priority_controls.main)
            #if os.path.exists('./artifacts/calledVulnerableFunctionsObjectList.txt'):
                #return render_template('vulResult.html')
            context = {
                        "Reachable_vulns": "test is finished"
                    }
            logging.info(f"Context: {context}")
        except Exception as e:
            app.logger.error(f"Error saving file: {e}")
            return 'Error saving file', 500
    return jsonify(message="Vulnerability Effectivenes Test Finished.", status=200), 200


@dependencies_blueprint.route('/dependencies/directory', methods=['POST'])
def dependencies_directory():
    """
    Handle directory upload for project analysis.
    Accepts multiple files from a directory upload and preserves the directory structure.
    Also handles controls file upload and triggers analysis when both are present.
    """
    try:
        # Check if files are present in the request
        if 'files' not in request.files:
            logging.error("No files in directory upload request.")
            return jsonify(error="No files provided"), 400

        files = request.files.getlist('files')
        if not files or len(files) == 0:
            logging.error("Empty file list in directory upload request.")
            return jsonify(error="No files selected"), 400

        # Check for controls file upload
        if 'controls_file' not in request.files:
            logging.error("No controls file in directory upload request.")
            return jsonify(error="Controls file is required"), 400

        controls_file = request.files['controls_file']
        if controls_file.filename == '':
            logging.error("No controls file selected.")
            return jsonify(error="Controls file is required"), 400

        # Extract entry point parameters from form
        module_name = request.form.get('module_name')
        function_name = request.form.get('function_name')

        # Validate entry point parameters
        if not module_name or not function_name:
            logging.error("Missing entry point parameters for directory upload.")
            return jsonify(error="Module name and function name are required"), 400

        logging.info(f"Directory upload - Entry point parameters - Module: {module_name}, Function: {function_name}")
        logging.info(f"Directory upload - Received {len(files)} files")
        logging.info(f"Controls file: {controls_file.filename}")

        # Define the target directory (where analysis pipeline expects files)
        dependencies_dir = os.path.join(os.getcwd(), "app", "dependencies")
        logging.info(f"Target dependencies directory: {dependencies_dir}")

        # Ensure the dependencies directory exists
        os.makedirs(dependencies_dir, exist_ok=True)

        # Clear existing contents of dependencies directory
        logging.info("Clearing existing dependencies directory contents")
        if not clear_dependencies_directory():
            logging.error("Failed to clear dependencies directory")
            return jsonify(error="Failed to prepare dependencies directory for upload"), 500

        # Validate project structure before processing
        validation_result = validate_project_structure(files)
        if not validation_result['is_valid']:
            logging.error(f"Project validation failed: {validation_result['error']}")
            return jsonify(error=validation_result['error']), 400

        logging.info(f"✓ Project validation passed - requirements.txt found at: {validation_result['requirements_path']}")

        # Track upload statistics and validation
        uploaded_files = []
        created_directories = set()

        logging.info("=== Starting file extraction with complete structure preservation ===")

        # Process each uploaded file with enhanced structure preservation
        for file in files:
            if file.filename == '':
                logging.warning("Skipping file with empty filename")
                continue

            # Get the relative path from the file (webkitdirectory preserves structure)
            relative_path = file.filename
            logging.info(f"Processing file: {relative_path}")

            # Validate and normalize the path
            if not relative_path or relative_path.startswith('/') or '..' in relative_path:
                logging.error(f"Invalid or unsafe file path: {relative_path}")
                return jsonify(error=f"Invalid file path: {relative_path}"), 400

            # Enhanced path processing with complete structure preservation
            try:
                # Normalize path separators and split into components
                normalized_path = relative_path.replace('\\', '/')  # Handle Windows paths
                path_parts = [part for part in normalized_path.split('/') if part]

                # Secure each path component while preserving structure
                secured_parts = []
                for part in path_parts:
                    secured_part = secure_filename(part)
                    if not secured_part:  # secure_filename returned empty string
                        logging.error(f"Unable to secure filename component: {part}")
                        return jsonify(error=f"Invalid filename component: {part}"), 400
                    secured_parts.append(secured_part)

                # Reconstruct the secured relative path
                secured_relative_path = '/'.join(secured_parts)

                # Create the full target path
                target_path = os.path.join(dependencies_dir, secured_relative_path)

                # Ensure target path is within dependencies directory (security check)
                if not os.path.abspath(target_path).startswith(os.path.abspath(dependencies_dir)):
                    logging.error(f"Path traversal attempt detected: {relative_path}")
                    return jsonify(error="Invalid file path detected"), 400

                # Create directory structure if needed
                target_dir = os.path.dirname(target_path)
                if target_dir and target_dir != dependencies_dir:
                    os.makedirs(target_dir, exist_ok=True)
                    created_directories.add(target_dir)
                    logging.info(f"✓ Created directory structure: {os.path.relpath(target_dir, dependencies_dir)}")

                # Save the file with preserved structure
                file.save(target_path)
                uploaded_files.append({
                    'original_path': relative_path,
                    'target_path': target_path,
                    'relative_target': os.path.relpath(target_path, dependencies_dir)
                })
                logging.info(f"✓ Saved file: {os.path.relpath(target_path, dependencies_dir)}")

            except Exception as e:
                logging.error(f"Error processing file {relative_path}: {e}")
                return jsonify(error=f"Error processing file {relative_path}: {str(e)}"), 500

        # Copy requirements.txt to expected location for prepareProject.py
        logging.info("=== Copying requirements.txt to expected location ===")
        if not find_and_copy_requirements_file(dependencies_dir, uploaded_files):
            logging.error("Failed to copy requirements.txt to expected location")
            return jsonify(error="Failed to prepare requirements.txt for analysis"), 500

        # Validate upload completeness and structure preservation
        logging.info("=== Upload validation and structure verification ===")

        # Log upload statistics
        logging.info(f"✓ Upload completed successfully:")
        logging.info(f"  - Files uploaded: {len(uploaded_files)}")
        logging.info(f"  - Directories created: {len(created_directories)}")

        # Verify structure preservation by checking key files
        requirements_path = os.path.join(dependencies_dir, 'requirements.txt')
        if os.path.exists(requirements_path):
            logging.info(f"✓ Verified requirements.txt at expected location: {requirements_path}")
        else:
            logging.error(f"❌ Requirements.txt not found at expected location: {requirements_path}")
            return jsonify(error="Structure preservation failed - requirements.txt not at expected location"), 500

        # Log the final directory structure for verification
        logging.info("=== Final directory structure in dependencies ===")
        try:
            for root, dirs, files in os.walk(dependencies_dir):
                level = root.replace(dependencies_dir, '').count(os.sep)
                indent = ' ' * 2 * level
                rel_root = os.path.relpath(root, dependencies_dir) if root != dependencies_dir else '.'
                logging.info(f"{indent}{rel_root}/")
                subindent = ' ' * 2 * (level + 1)
                for file in files:
                    logging.info(f"{subindent}{file}")
        except Exception as e:
            logging.warning(f"Could not log directory structure: {e}")

        logging.info("=== Structure preservation completed successfully ===")

        # Process controls file upload
        logging.info("=== Processing controls file upload ===")
        try:
            controls_file_path = os.path.join(app.config['UPLOAD_FOLDER'], controls_file.filename)
            controls_file.save(controls_file_path)
            logging.info(f"✓ Controls file saved to: {controls_file_path}")
            
            # Log controls file content for debugging
            with open(controls_file_path, 'r') as f:
                logging.info(f"Controls file content preview: {f.read()[:200]}...")
                
        except Exception as e:
            logging.error(f"Error saving controls file: {e}")
            return jsonify(error=f"Error processing controls file: {str(e)}"), 500

        logging.info("Directory upload and controls file upload completed successfully")
        logging.info(f"Starting analysis pipeline with module: {module_name}, function: {function_name}")

        # Run the existing analysis pipeline (same as single file upload)
        subprocess.run(["python3", "./app/prepareProject.py", module_name, function_name])
        createThread(cwe_cve_to_techniques.main)
        createThread(priority_controls.main)

        context = {
            "Reachable_vulns": "Directory analysis test is finished"
        }
        logging.info(f"Directory upload context: {context}")

        return jsonify(message="Directory Upload and Vulnerability Analysis Finished.", status=200), 200

    except Exception as e:
        logging.error(f"Error in directory upload: {e}")
        app.logger.error(f"Error in directory upload: {e}")
        return jsonify(error=f"Error processing directory upload: {str(e)}"), 500
