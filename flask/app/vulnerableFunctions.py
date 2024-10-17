from flask import Blueprint, jsonify
import ast
import json
import logging
import os
import time

vulnerable_blueprint = Blueprint('vulnerable', __name__)
logging.basicConfig(level=logging.INFO)

def load_data():
    # get the current directory
    cur_dir = os.path.abspath(os.path.dirname(__file__))
    """Load input data from JSON files."""
    vulnerable_functions_path = os.path.join(cur_dir, "artifacts", 'calledVulnerableFunctionsObjectList.txt')
    logging.info(f"Loading data from {vulnerable_functions_path}")
    time.sleep(3)
    
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



def create_vulntable(self):
        logging.info("Enterred create_vulntable method.")
        # creates html table by using the json file that just generated
        logging.info("Will open the calledVulnerableFunctionsObjectList.txt file and read the contents.")
        with open('./app/artifacts/calledVulnerableFunctionsObjectList.txt', 'r') as out_file:
            logging.info("Opened calledVulnerableFunctionsObjectList.txt file.")
            functionsData = out_file.read()
            logging.info("Read the contents of the file into the functionsData variable.")
            functionsData = functionsData.split('\n') # List of strings
            logging.info("Split the contents of the file by newline.")
            json_objects_list = [] # List of dictionaries
            logging.info("Declared json_objects_list list.")
            logging.info("Will iterate through the functionsData. For each data in the list, we will append the data to the json_objects_list list.")
            for data in functionsData:
                logging.info(f"Data item in functionsData: {data}")
                logging.info(f"Type of data item: {type(data)}")
                if data != '':
                    logging.info("Data item is not empty.")
                    logging.info("Will append the data to the json_objects_list list.")
                    json_objects_list.append(eval(data)) # convert string to dictionary
            logging.info(type(json_objects_list))

            return json_objects_list


def createJSONFromDictList(dict_list):
        my_dict = {}
        for d in dict_list:
            for k, v in d.items():
                my_dict[k] = v
        return my_dict



@vulnerable_blueprint.route('/vulnerable_functions', methods=['GET','POST'])
def vulnerable():
    data = load_data()
    # Create the vulntable
    dictionary_list = create_vulntable(data)

    # Create JSON from dictionary list
    json_data = createJSONFromDictList(dictionary_list)

    logging.info(f"JSON data: {json_data}")

    return json_data


def main():
     pass

if __name__ == "__main__":
    # Load data from JSON files
    main()

    
    
    #logging.info("Returned from create_vulntable method