import json
import os
import logging
from datetime import datetime

def process_inspec_results(input_file, output_file):
    """
    Process InSpec JSON results and convert to the format expected by the frontend.

    Args:
        input_file (str): Path to the InSpec JSON output file
        output_file (str): Path to write the processed results
    
    Returns:
        bool: True if processing was successful, False otherwise
    """
    logging.info(f"Processing InSpec results from {input_file} to {output_file}")

    # Check if input file exists
    if not os.path.isfile(input_file):
        logging.error(f"ERROR: Input file {input_file} does not exist")
        return False

    try:
        # Read the InSpec JSON output
        with open(input_file, 'r') as f:
            inspec_data = json.load(f)
            file_size = os.path.getsize(input_file)
            logging.info(f"Read {file_size} bytes from {input_file}")

        # Print the structure of the file
        logging.info("\n=== InSpec Output Structure ===")
        logging.info(f"Top-level keys: {list(inspec_data.keys())}")

        if 'profiles' in inspec_data:
            logging.info(f"Number of profiles: {len(inspec_data['profiles'])}")
            for i, profile in enumerate(inspec_data['profiles']):
                logging.info(f"\nProfile #{i+1}:")
                logging.info(f"  Name: {profile.get('name', 'unknown')}")
                logging.info(f"  Title: {profile.get('title', 'unknown')}")
                logging.info(f"  Profile keys: {list(profile.keys())}")

                if 'controls' in profile:
                    controls = profile['controls']
                    logging.info(f"  Number of controls: {len(controls)}")
                    for j, control in enumerate(controls[:3]):  # Show first 3 controls only
                        logging.info(f"    Control #{j+1}:")
                        logging.info(f"      ID: {control.get('id', 'unknown')}")
                        logging.info(f"      Title: {control.get('title', 'unknown')}")
                        logging.info(f"      Control keys: {list(control.keys())}")

                        if 'results' in control:
                            results = control['results']
                            logging.info(f"      Number of results: {len(results)}")
                            if results:
                                logging.info(f"      First result keys: {list(results[0].keys())}")
                                logging.info(f"      First result status: {results[0].get('status', 'unknown')}")

                    if len(controls) > 3:
                        logging.info(f"    ... and {len(controls) - 3} more controls")

        logging.info("=== End of Structure ===\n")

        # Initialize results list
        results = []

        # Check if profiles exist in the data
        if 'profiles' not in inspec_data or not inspec_data['profiles']:
            logging.error("ERROR: No profiles found in InSpec output")
            logging.info(f"Keys in data: {list(inspec_data.keys())}")
            return False

        # Process each profile
        total_controls = 0
        for profile in inspec_data['profiles']:
            profile_name = profile.get('name', 'unknown')
            # Process controls in the profile
            if 'controls' in profile:
                controls = profile['controls']
                total_controls += len(controls)
                logging.info(f"Processing profile '{profile_name}' with {len(controls)} controls")

                for control in controls:
                    # Extract control ID
                    control_id = control.get('id', '').lower()

                    # Map control IDs to expected format if needed
                    control_id = map_control_id(control_id)

                    logging.info(f"Processing control: {control_id} (original ID: {control.get('id', '')})")

                    # Skip if no control ID
                    if not control_id:
                        logging.warning(f"WARNING: Control without ID found in profile {profile_name}")
                        continue

                    # Determine overall status for the control
                    control_results = control.get('results', [])
                    if not control_results:
                        logging.warning(f"WARNING: Control {control_id} has no results")
                        continue

                    # If any test failed, the control status is failed
                    status = 'passed'
                    for result in control_results:
                        if result.get('status') != 'passed':
                            status = 'failed'
                            break

                    # Collect test results
                    test_results = []
                    for result in control_results:
                        # Clean up test name by removing redundant phrases
                        test_name = result.get('code_desc', 'Unknown test')
                        
                        # Remove redundant phrases like "should allow access to user profile"
                        # but preserve phrases that are essential like "is expected to include"
                        if " should " in test_name and not " is expected to " in test_name:
                            test_name = test_name.split(" should ")[0]
                        
                        test_results.append({
                            'test_name': test_name,
                            'status': result.get('status', 'unknown')
                        })

                    # Add the control to the results
                    results.append({
                        'control_id': control_id,
                        'status': status,
                        'test_results': test_results
                    })

        logging.info(f"InSpec output contains {total_controls} controls")

        # If no controls were found, return error
        if not results:
            logging.error("ERROR: No controls found in InSpec output")
            return False

        # Read existing results if the file exists
        existing_results = []
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    file_content = json.load(f)

                    # Check if the file has the new format with metadata
                    if isinstance(file_content, dict) and 'results' in file_content:
                        existing_results = file_content.get('results', [])
                    else:
                        # Old format (just an array)
                        existing_results = file_content if isinstance(file_content, list) else []

                logging.info(f"Read {len(existing_results)} existing controls from {output_file}")
            except Exception as e:
                logging.warning(f"Failed to read existing results from {output_file}: {str(e)}")
                existing_results = []

        # Merge results, replacing existing controls with the same ID
        merged_results = []
        existing_control_ids = set()

        # Add existing controls that are not in the new results
        for existing_control in existing_results:
            # Handle different formats of existing controls
            if isinstance(existing_control, dict):
                existing_id = existing_control.get('control_id')
                if existing_id:
                    existing_control_ids.add(existing_id)

                    # Check if this control is in the new results
                    if not any(r.get('control_id') == existing_id for r in results):
                        merged_results.append(existing_control)
            else:
                logging.warning(f"Skipping invalid existing control: {existing_control}")

        # Add all new results
        merged_results.extend(results)

        # Add timestamp to the merged results
        timestamp = datetime.now().isoformat()

        # Write the merged results to the output file
        with open(output_file, 'w') as f:
            # Add a metadata object with timestamp
            final_output = {
                "metadata": {
                    "timestamp": timestamp,
                    "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                },
                "results": merged_results
            }
            json.dump(final_output, f, indent=2)

        # After writing the file
        file_stat = os.stat(output_file)
        logging.info(f"File {output_file} written with size {file_stat.st_size} bytes")
        logging.info(f"File modification time: {datetime.fromtimestamp(file_stat.st_mtime).isoformat()}")

        logging.info(f"Successfully wrote {len(merged_results)} controls to {output_file}")
        logging.info(f"Merged results contain controls: {[r.get('control_id') for r in merged_results]}")

        # Log the first few results for debugging
        if results:
            logging.info("Sample of processed results:")
            for i, result in enumerate(results[:2]):  # Show first 2 results
                logging.info(f"  Result #{i+1}:")
                logging.info(f"    Control ID: {result['control_id']}")
                logging.info(f"    Status: {result['status']}")
                logging.info(f"    Number of test results: {len(result['test_results'])}")

        return True

    except Exception as e:
        logging.error(f"ERROR: Failed to process InSpec results: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def map_control_id(control_id):
    """Map InSpec control IDs to NIST control IDs"""
    mapping = {
        'authentication-policy': 'ia-2',
        'audit-policy': 'au-2',
        'audit-content': 'au-3',
        'audit-storage': 'au-4',
        'audit-response': 'au-5',
        'audit-review': 'au-6',
        'audit-timestamps': 'au-8',
        'audit-protection': 'au-9',
        'audit-nonrepudiation': 'au-10',
        'audit-retention': 'au-11',
        'audit-generation': 'au-12',
        'cross-organizational-auditing': 'au-16',
        'access-control-policy': 'ac-3',
        'account-management': 'ac-2',
        'configuration-management-policy': 'cm-2',
        'baseline-configuration': 'cm-2',
        'access-restrictions-for-change': 'cm-5',
        'system-component-inventory': 'cm-8',
        'input-validation-policy': 'si-10',
        'session-crypto-policy': 'sc-8',
        'malicious-code-protection-policy': 'si-3',
        'boundary-protection-policy': 'sc-7',
        'data-protection-policy': 'sc-28'
    }
    return mapping.get(control_id, control_id)