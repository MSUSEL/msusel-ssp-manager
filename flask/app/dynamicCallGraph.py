import cProfile
import pstats
import json
import importlib
import importlib.util
import sys
import logging
import os

logging.basicConfig(level=logging.INFO)

def dynamic_import(module_name, function_name):
    try:
        logging.info(f"Importing module '{module_name}'...")

        # Get user project path from environment variable (set by ProfilerLauncher)
        user_project_path = os.environ.get('USER_PROJECT_PATH')

        if user_project_path:
            # Clean subprocess environment - use environment variable
            dependencies_dir = user_project_path
            logging.info(f"Using USER_PROJECT_PATH from environment: {dependencies_dir}")
        else:
            # Fallback to legacy path calculation (for backward compatibility)
            current_dir = os.getcwd()
            dependencies_dir = os.path.join(current_dir, "app", "dependencies")
            logging.info(f"Using legacy path calculation: {dependencies_dir}")

        # Ensure the dependencies directory exists
        if not os.path.exists(dependencies_dir):
            raise ImportError(f"Dependencies directory not found: {dependencies_dir}")

        logging.info(f"Dependencies directory: {dependencies_dir}")
        logging.info(f"Initial sys.path: {sys.path}")

        # Add dependencies directory to Python path if not already present
        # Insert at the end to ensure standard library takes precedence
        if dependencies_dir not in sys.path:
            sys.path.append(dependencies_dir)
            logging.info(f"Added dependencies directory to sys.path: {dependencies_dir}")

        # Only add immediate subdirectories that look like user project directories
        # Skip dependency source code, examples, tests, etc.
        skip_patterns = ['examples', 'tests', 'test', 'demos', 'sample', 'tutorial', '__pycache__', '.git', 'site-packages']
        
        try:
            for item in os.listdir(dependencies_dir):
                item_path = os.path.join(dependencies_dir, item)
                
                logging.info(f"Processing item: {item} -> {item_path}")
                
                # Only process directories
                if not os.path.isdir(item_path):
                    logging.info(f"Skipping {item} (not a directory)")
                    continue
                    
                # Skip directories that match problematic patterns
                if any(pattern.lower() in item.lower() for pattern in skip_patterns):
                    logging.info(f"Skipping directory (matches skip pattern): {item_path}")
                    continue
                
                logging.info(f"Analyzing directory: {item_path}")
                
                # Check if this directory should be added to sys.path
                should_add = False
                
                # Option 1: Directory contains Python files directly
                try:
                    for file in os.listdir(item_path):
                        if file.endswith('.py'):
                            should_add = True
                            logging.info(f"Directory contains Python files: {item_path}")
                            break
                except (PermissionError, OSError):
                    continue
                
                # Option 2: Directory contains Python packages (subdirectories with __init__.py)
                if not should_add:
                    try:
                        logging.info(f"Checking for packages in directory: {item_path}")
                        for subitem in os.listdir(item_path):
                            subitem_path = os.path.join(item_path, subitem)
                            logging.info(f"  Checking subitem: {subitem} -> {subitem_path}")
                            if os.path.isdir(subitem_path):
                                init_file = os.path.join(subitem_path, '__init__.py')
                                logging.info(f"    Is directory, checking for __init__.py: {init_file}")
                                if os.path.exists(init_file):
                                    should_add = True
                                    logging.info(f"Directory contains Python package '{subitem}': {item_path}")
                                    break
                                else:
                                    logging.info(f"    No __init__.py found in {subitem_path}")
                            else:
                                logging.info(f"    {subitem} is not a directory")
                    except (PermissionError, OSError) as e:
                        logging.warning(f"Could not scan directory {item_path}: {e}")
                        continue
                
                if should_add and item_path not in sys.path:
                    sys.path.append(item_path)
                    logging.info(f"Added user project directory to sys.path: {item_path}")
                elif not should_add:
                    logging.info(f"Skipping directory (no Python files or packages): {item_path}")
                    
        except (PermissionError, OSError) as e:
            logging.warning(f"Could not scan dependencies directory: {e}")

        logging.info(f"Final sys.path: {sys.path}")

        # Test if the module can be found before importing
        spec = importlib.util.find_spec(module_name)
        if spec is None:
            logging.error(f"Module '{module_name}' not found in Python path")
            logging.info(f"Current sys.path: {sys.path}")

            # List available Python files in dependencies directory for debugging
            try:
                python_files = []
                for root, dirs, files in os.walk(dependencies_dir):
                    for file in files:
                        if file.endswith('.py'):
                            rel_path = os.path.relpath(os.path.join(root, file), dependencies_dir)
                            python_files.append(rel_path)
                logging.info(f"Available Python files in dependencies: {python_files}")
            except Exception as e:
                logging.warning(f"Could not list Python files: {e}")

            raise ImportError(f"No module named '{module_name}'")
        
        logging.info(f"Module '{module_name}' found at: {spec.origin}")
        
        # Import the module dynamically
        module = importlib.import_module(module_name)
        
        # Verify the function exists in the module
        if not hasattr(module, function_name):
            available_functions = [name for name in dir(module) if callable(getattr(module, name)) and not name.startswith('_')]
            logging.error(f"Function '{function_name}' not found in module '{module_name}'")
            logging.info(f"Available functions in module: {available_functions}")
            raise AttributeError(f"Module '{module_name}' has no function '{function_name}'")
        
        function = getattr(module, function_name)
        logging.info(f"Function '{function_name}' found in module '{module_name}'")
        print(f"Module '{module_name}' imported successfully!")
        
    except ImportError as e:
        logging.error(f"ImportError: {e}")
        print(f"Failed to import module '{module_name}': {e}")
        raise
    except AttributeError as e:
        logging.error(f"AttributeError: {e}")
        print(f"Failed to find function '{function_name}' in module '{module_name}': {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error during import: {e}")
        print(f"Unexpected error importing module '{module_name}': {e}")
        raise
    
    return module, function


def runProfiler(main_function):
    # Start profiling
    profiler = cProfile.Profile()
    profiler.enable()

    # Run program
    main_function()

    # Stop profiling
    profiler.disable()

    # Save profiling data in a Stats object
    stats = pstats.Stats(profiler)

    # Convert profiling data to a JSON-compatible dictionary
    stats_dict = {
        "functions": [],
        "total_time": stats.total_tt,
        "primitive_calls": stats.prim_calls,
        "total_calls": stats.total_calls,
    }

    for func in stats.stats:
        filename, line_number, func_name = func
        stats_dict["functions"].append({
            "filename": filename,
            "line_number": line_number,
            "function_name": func_name,
            "total_time": stats.stats[func][2],
            "ncalls": stats.stats[func][0],
            "ccalls": stats.stats[func][1],
            "nactualcalls": stats.stats[func][3],
        })

    # Save the JSON data to a file using absolute path
    current_dir = os.getcwd()
    logging.info(f"Current directory: {current_dir}")

    # Get artifacts path from environment variable (set by ProfilerLauncher)
    artifacts_path = os.environ.get('ARTIFACTS_PATH')

    if artifacts_path:
        # Clean subprocess environment - use environment variable
        artifacts_dir = artifacts_path
        logging.info(f"Using ARTIFACTS_PATH from environment: {artifacts_dir}")
    else:
        # Fallback to legacy path calculation (for backward compatibility)
        artifacts_dir = os.path.join(current_dir, "app", "artifacts")
        logging.info(f"Using legacy artifacts path calculation: {artifacts_dir}")

    output_path = os.path.join(artifacts_dir, "profile_data.json")

    # Ensure artifacts directory exists
    os.makedirs(artifacts_dir, exist_ok=True)

    with open(output_path, "w") as json_file:
        json.dump(stats_dict, json_file, indent=4)

    logging.info(f"Profile data saved to: {output_path}")

'''
def startProfiler(module_name, function_name):
    module, function_name  = dynamic_import(module_name, function_name)
    runProfiler(function_name)
'''

if __name__ == "__main__":
    module_name = sys.argv[1]
    function_name = sys.argv[2]
    module, function_name  = dynamic_import(module_name, function_name)
    logging.info(f"Running profiler for function '{function_name}' in module '{module_name}'")
    runProfiler(function_name)
    logging.info("Profiling completed!")
