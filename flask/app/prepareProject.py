# This program creates a virtual environment in the curtent directory.

import os
import sys
import subprocess
import platform
import importlib
import shutil
from downloadDependencies import download_Dependencies
from copySTDLIBfiles import copySTDLibFiles
from runBandit import runBandit
from parseBanditOutput import parseBandit
from getFunctionNames import getVulnerableFunctions
from parseProfile import getFilesAndFunctionNamesFromCallGraph
from matchVulnerabilitiesToCalls import matchVulnerableFunctionsToCalledFunctions
from prepareCWEList import prepareCWEList
import logging

logging.basicConfig(level=logging.INFO)


# This function installs Python's venv module.
def installVenv():
    # Check if the venv module is installed
    try:
        importlib.import_module('venv')
    except ImportError:
        print("The venv module is not installed.")
        # Handle: Install the venv module
        if platform.system() == "Windows":
            subprocess.run(["python", "-m", "pip", "install", "venv"])
        else:
            subprocess.run(["python3", "-m", "pip", "install", "venv"])
        # Check if the venv module was installed
        try:
            importlib.import_module('venv')
        except ImportError:
            print("The venv module was not installed.")
            sys.exit()
        print("The venv module was installed.")

def createVenv():
    # Get the current directory
    currentDir = os.getcwd()
    # Check if the current directory is a valid directory
    if not os.path.isdir(currentDir):
        print("The current directory is not a valid directory.")
        sys.exit()
    # Create a venv virtual environment
    if platform.system() == "Windows":
        subprocess.run(["python", "-m", "venv", "venv"])
    else:
        subprocess.run(["python3", "-m", "venv", "venv"])
    # Check if the venv directory was created
    if not os.path.isdir("venv"):
        print("The venv directory was not created.")
        sys.exit()
    # Print the message
    print("The venv directory was created.")

# This function activates the virtual environment
def activateVenv():
    activate_command = "source venv/bin/activate"  # For Unix-based systems
    # activate_command = "my_venv\\Scripts\\activate"  # For Windows systems
    # call the shell explicitly
    subprocess.run(["/bin/bash", "-c", activate_command], check=True)

def installRequirements():
    currentDir = os.getcwd()
    # Install a package in the virtual environment
    # Give the path to the pip executable
    pip_path = "venv/bin/pip"  # For Unix-based systems
    subprocess.run([pip_path, "install", '-r', f'{currentDir}' + '/dependencies/requirements.txt' ], check=True)
    
def listInstalledPackages():
    # List the installed packages in the virtual environment
    # Give the path to the pip executable
    pip_path = "venv/bin/pip"  # For Unix-based systems
    pip_list_output = subprocess.run([pip_path, "list"], check=True, text=True)
    print("Installed packages in virtual environment:")
    print(pip_list_output.stdout)


def listAllDependencies():
    pip_path = "venv/bin/pip"  # For Unix-based systems. Give the path to the pip executable.
    with open('./artifacts/dependencies.txt', 'w') as f:
        subprocess.run([pip_path, 'freeze'], stdout=f)

def copyFile(filename):
    currentDir = os.getcwd()
    logging.info(f"Current directory: {currentDir}")
    originalPath = currentDir + filename
    logging.info(f"Original path: {originalPath}")
    newPath = currentDir + "/dependencies/" + filename
    logging.info(f"New path: {newPath}")
    shutil.copy(originalPath, newPath)
    return newPath

def removeFile(path):
    os.remove(path)

def profilerWrapper(module_name, function_name):
    currentDir = os.getcwd()
    logging.info(f"Current directory: {currentDir}")
    newPath = copyFile('dynamicCallGraph.py')
    result = subprocess.run(["python3", "./app/dependencies/dynamicCallGraph.py", f'{module_name}', f'{function_name}'], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(result.stdout.decode())
    print(result.stderr.decode())
    removeFile(newPath)


def copyToSTDLib():
    # Define the source and destination file paths
    source_file = 'sqLib.py'
    destination_file = '/usr/local/lib/python3.10/sqLib.py'

    # Use subprocess.run to copy the file
    try:
        subprocess.run(['sudo', 'cp', source_file, destination_file], check=True)
        print(f'Successfully copied {source_file} to {destination_file}')
    except subprocess.CalledProcessError as e:
        print(f'Failed to copy file: {e}')

def main_function():
    installVenv()
    createVenv()
    activateVenv()
    installRequirements()
    listInstalledPackages()
    listAllDependencies()
    download_Dependencies()
    copySTDLibFiles()
    runBandit()
    parseBandit()
    getVulnerableFunctions()  
    # Generate the dynamic call graph
    print(sys.argv[1], sys.argv[2])
    currentDir = os.getcwd()
    logging.info(f"Current directory: {currentDir}")
    profilerWrapper(sys.argv[1], sys.argv[2])
    # Parse the dynamic analysis results
    getFilesAndFunctionNamesFromCallGraph() 
    # Match the vulnerable functions with the dynamic analysis results
    matchVulnerableFunctionsToCalledFunctions()
    prepareCWEList()

if __name__ == "__main__":
    main_function()