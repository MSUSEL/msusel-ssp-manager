# This program reads  a catalog.json file in OSCAL format
# and extracts some attributes and their values and writes tehm to a new json file.
# The new json is feed as the data for the controls in the catalog of the REACT dashboard.
import json

# Load the original JSON file
file_path = 'NIST_SP-800-53_rev5_catalog.json'
with open(file_path, 'r') as f:
    data = json.load(f)

# Function to recursively extract statements
def extract_statements(parts):
    statements = []
    for part in parts:
        if 'prose' in part:
            statements.append(part['prose'])
        if 'parts' in part:
            statements.extend(extract_statements(part['parts']))
    return statements

# Extract the relevant information
controls = []

for group in data['catalog']['groups']:
    for control in group['controls']:
        control_info = {
            'id': control['id'],
            'title': control.get('title', ''),
            'statements': [],
            'guidance': ''
        }
        for part in control.get('parts', []):
            if part['name'] == 'statement':
                control_info['statements'].extend(extract_statements([part]))
            elif part['name'] == 'guidance':
                control_info['guidance'] = part.get('prose', '')
        controls.append(control_info)

# Save the extracted information to a new JSON file
extracted_file_path = '../public/example.json' # NEeds to be moved to the /public/ directory
with open(extracted_file_path, 'w') as f:
    json.dump(controls, f, indent=2)

extracted_file_path