# This program takees MITRE's technique to controls mappings
# and creates a list of dictionaries with the following keys:

'''
Example of a dictionary in the "mapping_objects" key:
      "capability_id": "SC-18",
      "capability_description": "Mobile Code",
      "attack_object_id": "T1055.013",
      "attack_object_name": "Process Doppelgänging",
      "references": [],
      "capability_group": "SC",
      "mapping_type": "protects",
      "status": "complete"

Example of a dictionary in the list of dictionaries:
        "Control_Name": "Concurrent Session Control",
        "Mapping_Type": "mitigates",
        "Technique_ID": "T1137",
        "Technique_Name": "Office Application Startup"    
'''

import json
import sys 

# List of dictionaries
mapping_objects = []

# Read the json file name from the command line
json_file = sys.argv[1]

# Open the json file
with open(json_file) as f:
    data = json.load(f)

# Print the values of the "capability_id" key
for item in data['mapping_objects']:
    #print(item['capability_id'])

    # Create a dictionary with the value of the "capability_id" key
    if item['capability_id'] != None:
        mapping_objects.append({'Control_ID': item['capability_id'], 'Control_Name': item['capability_description'], 'Mapping_Type': item['mapping_type'], 'Technique_ID': item['attack_object_id'], 'Technique_Name': item['attack_object_name']})

# Write the list of dictionaries to a json file
with open('nist800-53-r5-mappings2.json', 'w') as f:
    json.dump(mapping_objects, f, indent=4)