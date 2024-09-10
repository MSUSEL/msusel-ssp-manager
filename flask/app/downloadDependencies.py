# This program downloads the source code for the direct and indirect dependencies 
# for the project.
import os
import subprocess
import zipfile
import tarfile
import codecs
import logging

logging.basicConfig(level=logging.INFO)


# Function to remove the BOM from a file (invisible character at the beginning of the file)
def remove_bom_from_file(filename):
    # Open the file using UTF-8-SIG to automatically remove BOM
    with codecs.open(filename, 'r', 'utf-8-sig') as f:
        content = f.read()

    # Write the content back to the file using standard UTF-8
    with codecs.open(filename, 'w', 'utf-8') as f:
        f.write(content)


def extractSourceCode(name):
    # Get the name of the downloaded file
    filesList = os.listdir('./app/dependencies/' + name)
    file = ''
    if filesList != []:
        file = filesList[0]
    # Check if the file is a zip file
    if file.endswith('.zip'):
        # Extract the source code from the zip file
        with zipfile.ZipFile('./app/dependencies/' + name + '/' + file, 'r') as zip_ref:
            zip_ref.extractall('./app/dependencies/' + name)
    # Check if the file is a tar file
    elif file.endswith('.tar.gz'):
        # Extract the source code from the tar file
        with tarfile.open('./app/dependencies/' + name + '/' + file, 'r:gz') as tar_ref:
            tar_ref.extractall('./app/dependencies/' + name)
    # Check if the file is a tar file
    elif file.endswith('.tar'):
        # Extract the source code from the tar file
        with tarfile.open('./app/dependencies/' + name + '/' + file, 'r') as tar_ref:
            tar_ref.extractall('./app/dependencies/' + name)
    # Check if the file is a tar file
    elif file.endswith('.tgz'):
        # Extract the source code from the tar file
        with tarfile.open('./app/dependencies/' + name + '/' + file, 'r:gz') as tar_ref:
            tar_ref.extractall('./app/dependencies/' + name)
    # Check if the file is a tar file
    elif file.endswith('.tar.bz2'):
        # Extract the source code from the tar file
        with tarfile.open('./app/dependencies/' + name + '/' + file, 'r:bz2') as tar_ref:
            tar_ref.extractall('./app/dependencies/' + name)
    # Check if the file is a tar file
    elif file.endswith('.tar.xz'):
        # Extract the source code from the tar file
        with tarfile.open('./app/dependencies/' + name + '/' + file, 'r:xz') as tar_ref:
            tar_ref.extractall('./app/dependencies/' + name)
    # Check if the file is a tar file
    elif file.endswith('.tar.Z'):
        # Extract the source code from the tar file
        with tarfile.open('./app/dependencies/' + name + '/' + file, 'r:Z') as tar_ref:
            tar_ref.extractall('./app/dependencies/' + name)
    # Check if the file is a tar file
    elif file.endswith('.tar.lz'):
        # Extract the source code from the tar file
        with tarfile.open('./app/dependencies/' + name + '/' + file, 'r:lz') as tar_ref:
            tar_ref.extractall('./app/dependencies/' + name)
    # Check if the file is a tar file
    elif file.endswith('.tar.lzma'):
        # Extract the source code from the tar file
        with tarfile.open('./app/dependencies/' + name + '/' + file, 'r:xz') as tar_ref:
            tar_ref.extractall('./app/dependencies/' + name)
    # Check if the file is a tar file
    elif file.endswith('.tar.lzo'):
        # Extract the source code from the tar file
        with tarfile.open('./app/dependencies/' + name + '/' + file, 'r:lzo') as tar_ref:
            tar_ref.extractall('./app/dependencies/' + name)
    # Check if the file is a tar file
    elif file.endswith('.tar.Z'):
        # Extract the source code from the tar file
        with tarfile.open('./app/dependencies/' + name + '/' + file, 'r:Z') as tar_ref:
            tar_ref.extractall('./app/dependencies/' + name)
    

def downloadSourceCode(name, version):
    if version != '':
        # Download the source code for the dependency
        subprocess.run(['pip', 'download', '--no-binary', ':all:', '--no-deps', '-d', './app/dependencies/' + name, name + '==' + version])
    else:
        subprocess.run(['pip', 'download', '--no-binary', ':all:', '--no-deps', '-d', './app/dependencies/' + name, name])
    # Extract the source code from the downloaded file
    extractSourceCode(name)
    logging.info('Downloaded the source code for ' + name + ' ' + version)

# Function to download the source code for the package and direct dependencies.
# The function reads a text file containing the required packages names and versions.
def download_Dependencies():
    remove_bom_from_file('./app/artifacts/dependencies.txt')
    # Read the dependencies names and versions from the text file
    with open('./app/artifacts/dependencies.txt', 'r') as file:
        dependencies = file.readlines()
    # Remove the new line character from each dependency
    dependencies = [dep.strip() for dep in dependencies]
    # Create a directory to store the source code for the dependencies
    # This directory will store other directories for each dependency
    if not os.path.exists('./app/dependencies'):
        os.makedirs('./app/dependencies')
    # Loop through the dependencies
    for dep in dependencies:
        # Split the dependency into the name and version
        dep = dep.split('==')
        name = dep[0]
        if len(dep) != 1:
            version = dep[1]
        else:
            version = ''
        # Create a directory to store the source code for the particular dependency
        if not os.path.exists('./app/dependencies/' + name):
            os.makedirs('./app/dependencies/' + name)
        logging.info('Downloading the source code for ' + name + ' ' + version)
        # Download the source code for the dependency
        downloadSourceCode(name, version)
    logging.info("Downloaded the source code for the dependencies.")


# main function
def main():
    # Download the source code for the dependencies
    download_Dependencies()

if __name__ == '__main__':
    main()