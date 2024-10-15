import ast
import json
import logging
import os


def load_data():
    # get the current directory
    cur_dir = os.path.dirname(__file__)
    """Load input data from JSON files."""
    vulnerable_functions_path = os.path.join(cur_dir, "app/artifacts", 'calledVulnerableFunctionsObjectList.txt')
    
    # Load vulnerable functions as Python dicts
    vulnerable_functions = []
    with open(vulnerable_functions_path, 'r') as file:
        for line in file:
            if line.strip():  # Skip empty lines
                try:
                    # Use literal_eval to safely parse the string as a Python dict
                    vulnerable_functions.append(ast.literal_eval(line.strip()))
                except (SyntaxError, ValueError) as e:
                    logging.info(f"Could not parse line as dictionary: {line.strip()} - Error: {e}")

    return vulnerable_functions