# This program reads the profile_data.json file and saves the filename key and value 
# and the function_name key and value to a list of dictionaries. 
# The list of dictionaries is then written to a file called profile_data.txt.

import json

def getFilesAndFunctionNamesFromCallGraph():
    # Read the JSON data
    with open("./artifacts/profile_data.json", "r") as json_file:
        data = json.load(json_file)

    # Create a list of dictionaries
    profile_data = []

    # Iterate over the functions in the JSON data
    for dictionaries in data["functions"]:
        # dictionaries is a list of dictionaries.
        # Each dictionary has a filename and function_name keys. 
        # We create a individual dictionaries for each filename and for function_name key (and value).

        # Iterate over the list of dictionaries
        for key, value in dictionaries.items():
            if key == "filename" or key == "function_name":
                profile_data.append({key:value})  

    # Write the list of dictionaries to file.
    with open("./artifacts/profile_data.txt", "w") as txt_file:
        for item in profile_data:
            txt_file.write("%s\n" % item)
        print("./artifacts/The profile_data.txt file was created.")
