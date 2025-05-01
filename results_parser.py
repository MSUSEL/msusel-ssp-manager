import json

def print_json(data, indent=0):
    spacing = '  ' * indent
    if isinstance(data, dict):
        for key, value in data.items():
            print(f"{spacing}{key}:")
            print_json(value, indent + 1)
    elif isinstance(data, list):
        for index, item in enumerate(data):
            print(f"{spacing}- [{index}]")
            print_json(item, indent + 1)
    else:
        print(f"{spacing}{data}")

# Load the JSON file
with open('/home/ernesto/Documents/msusel-ssp-manager/flask/react-app/public/data/test_results.json', 'r') as file:
    data = json.load(file)

# Print all keys and values
print_json(data)
