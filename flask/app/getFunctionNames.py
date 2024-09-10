# This program reads a text file that contains a list of dictionaries. 
# Each dictionary contains the filename and the line number where the vulnerability occurs. 
# The program will then traverse the directories and  using the line_number values
# determine the name of the function where the vulnerability occurs. 
# The program will then write the results to a text file.
import ast
import codecs

# Function to remove the BOM from a file (invisible character at the beginning of the file)
def remove_bom_from_file(filename):
    # Open the file using UTF-8-SIG to automatically remove BOM
    with codecs.open(filename, 'r', 'utf-8-sig') as f:
        content = f.read()

    # Write the content back to the file using standard UTF-8
    with codecs.open(filename, 'w', 'utf-8') as f:
        f.write(content)



# This function will open the text file and return a list of dictionaries
def openFile():
    fileAndVulnerabilitiesLinesDictionaryList = []
    remove_bom_from_file('./app/artifacts/fileAndVulnerabilitiesLinesDictionaryList.txt')
    with open('./app/artifacts/fileAndVulnerabilitiesLinesDictionaryList.txt', 'r') as f:
        for line in f:
            fileAndVulnerabilitiesLinesDictionaryList.append(ast.literal_eval(line))
    f.close()
    return fileAndVulnerabilitiesLinesDictionaryList


# We have list of dictionaries.
# Each key has a value that is a line number.
# Many of the dictionaries have the same key.
# This function takes the list of dictionaries and returns another list of dictionaries 
# where there are no duplicate keys, and each key has a list of line numbers as it values.
# Whenever the keys are the same, the line numbers are appended to the list of line numbers.
def removeDuplicateKeys(fileAndVulnerabilitiesLinesDictionaryList):
    merged_dict = {}

    # Iterate over the list of dictionaries
    for d in fileAndVulnerabilitiesLinesDictionaryList:
        # Iterate over the key-value pairs in each dictionary
        for key, value in d.items():
            # Check if the key already exists in the merged dictionary
            if key in merged_dict:
                # If the key exists, append the value to the corresponding list
                merged_dict[key].append(value)
            else:
                # If the key does not exist, create a new list with the value
                merged_dict[key] = [value]

    # Convert the merged dictionary back to a list of dictionaries
    noDuplicateFilesList = [{key: value} for key, value in merged_dict.items()]

    # write the result to a file
    with open('./app/artifacts/noDuplicateFilesList.txt', 'w') as f:
        for item in noDuplicateFilesList:
            f.write("%s\n" % item)
    f.close()

    return noDuplicateFilesList
        

def find_function_name(code, line_number):
    # Parse the Python code into an AST
    tree = ast.parse(code)
    # Function to recursively search for the enclosing function
    def search_function(node):
        if hasattr(node, 'body'):
            for n in node.body:
                if isinstance(n, ast.FunctionDef) and n.lineno <= line_number <= n.end_lineno:
                    return n.name
                elif hasattr(n, 'body'):
                    result = search_function(n)
                    if result:
                        return result

    # Start searching from the top-level nodes
    function_name = search_function(tree)
    return function_name

def getFunctionNamesFromSourceFiles(filesAndLinesOfVulnerabilities):
    filesAndFunctionNames = []
    for i in range(len(filesAndLinesOfVulnerabilities)):
        for key, value in filesAndLinesOfVulnerabilities[i].items():
            tempDict = {} 
            tempDict[key] = []
            with open(key) as f:
                source_code = f.read()
            
            # Determine the name of the function that the line_number values correspond to.
            for i in range(len(value)):
                function_name = find_function_name(source_code, value[i])
                if function_name:
                    tempDict[key].append(function_name)
                
            f.close()
            filesAndFunctionNames.append(tempDict)

    for dict in filesAndFunctionNames:
        for key in dict:
            # Extract the list from the dictionary
            functionListWithDuplicates = dict[key]
            # Remove duplicates
            functionListNoDuplicates = list(set(functionListWithDuplicates))
            # Update the dictionary with the modified list
            dict[key] = functionListNoDuplicates
    
    # write the result to a file
    with open('./app/artifacts/filesAndFunctionNames.txt', 'w') as f:
        for item in filesAndFunctionNames:
            f.write("%s\n" % item)
    return filesAndFunctionNames


def getVulnerableFunctions():
    # Open the text file
    fileAndVulnerabilitiesLinesDictionaryList = openFile()
    filesAndLinesOfVulnerabilities = removeDuplicateKeys(fileAndVulnerabilitiesLinesDictionaryList)
    # Creates a filesAndFunctionNames.txt artifact
    getFunctionNamesFromSourceFiles(filesAndLinesOfVulnerabilities)


if __name__ == "__main__":
    getVulnerableFunctions()