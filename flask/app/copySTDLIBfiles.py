import os
import ast
import importlib.util
import shutil
import logging

logging.basicConfig(level=logging.INFO)

def get_imported_modules(directory):
    imported_modules = set()
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                with open(os.path.join(root, file), 'r') as f:
                    try:
                        tree = ast.parse(f.read(), filename=file)
                        for node in ast.walk(tree):
                            if isinstance(node, ast.Import):
                                for alias in node.names:
                                    imported_modules.add(alias.name)
                            elif isinstance(node, ast.ImportFrom):
                                if node.module:
                                    imported_modules.add(node.module)
                    except SyntaxError as e:
                        logging.info(f"SyntaxError in file {file}: {e}")
    return imported_modules

def is_standard_library(module_name):
    try:
        spec = importlib.util.find_spec(module_name)
        logging.info(f"Spec: {spec}")
        logging.info(f"Spec origin: {spec.origin}")
        if spec and spec.origin:
            return spec.origin and spec.origin.startswith('/usr/local/lib/python3.10')
    except ModuleNotFoundError:
        logging.info(f"ModuleNotFoundError: No module named '{module_name}'")
    except Exception as e:
        logging.info(f"Error finding spec for module '{module_name}': {e}")
    return False

def copy_standard_lib_files(module_name, destination):
    try:
        spec = importlib.util.find_spec(module_name)
        if spec and spec.origin:
            source_path = spec.origin
           
            if os.path.isdir(source_path):
                # If the module is a package, copy the whole directory
                shutil.copytree(source_path, os.path.join(destination, os.path.basename(source_path)), dirs_exist_ok=True)
            else:
                # If the module is a single file, copy the file
                os.makedirs(destination, exist_ok=True)
                shutil.copy2(source_path, destination)
           
            # Handle submodules
            submodules = []
            if spec.submodule_search_locations:
                for subdir in spec.submodule_search_locations:
                    for root, _, files in os.walk(subdir):
                        for file in files:
                            if file.endswith('.py'):
                                submodules.append(os.path.join(root, file))
           
            for submodule in submodules:
                submodule_dest = os.path.join(destination, os.path.relpath(submodule, start='/usr/lib/python3.11'))
                os.makedirs(os.path.dirname(submodule_dest), exist_ok=True)
                shutil.copy2(submodule, submodule_dest)
    except ModuleNotFoundError:
        logging.info(f"ModuleNotFoundError: No module named '{module_name}'")
    except Exception as e:
        logging.info(f"Error copying module '{module_name}': {e}")  

def copy_modules(imported_modules, destination):
    for module in imported_modules:
        if is_standard_library(module):
            copy_standard_lib_files(module, destination)
            logging.info(f"Successfully copied {module} to {destination}")

def copySTDLibFiles():
    logging.info("Copying standard library files...")
    source_directory = os.getcwd()
    logging.info(f"Source directory: {source_directory}")
    destination_directory = source_directory + '/app/dependencies'
    logging.info(f"Destination directory: {destination_directory}")
    imported_modules = get_imported_modules(destination_directory)
    logging.info(f"Imported modules: {imported_modules}")
    copy_modules(imported_modules, destination_directory)
