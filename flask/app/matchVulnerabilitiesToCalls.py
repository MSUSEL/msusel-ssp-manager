import json
import logging

logging.basicConfig(level=logging.INFO)

def getCalledFunctionName(input_string, split_string):
    # case ex: '<method 'find' of 'str'objects>'
    if split_string == "'":
        split_string = input_string.split("'") # We get a list of strings
        #print(split_string)
        # ['<method ', 'find', ' of ', 'str', ' objects>']
        if len(split_string) >= 3: # Before the first quote, before the 2nd, after the 2nd
            # Otherwise, we don't have a method name
            method_name = split_string[1] # Between the first and second quote
    
    if split_string == " ":
        split_string = input_string.split(" ")
        #print(input_string)
        #print(split_string)
        
        if "." in split_string[2]:
            # case ex: '<built-in method sys.audit>'
            method_name = split_string[2].split(".")[1][:-1] # Remove the last character
        elif "." in split_string[1]:
            # case ex: '<function HTTPResponse.flush at 0x7f9d74d27490>'
            method_name = split_string[1].split(".")[1]
        else:
            # case ex: '<built-in method from_bytes>'
            method_name = split_string[2][:-1] 
    
    # Check if the method name is valid before returning it
    if method_name:
        return method_name
    else:
        return "Method name not found."



def getListFromFile(filename):
    with open(filename) as f:
        list = f.readlines()
    # Remove the new line character from the list
    list = [x.strip() for x in list]
    return list


def getDictionaryList(strJsonList):
    dictionaryList = []
    # Iterate over the list of jsonStrings
    for strJson in strJsonList:
        # Convert from string to dictionary
        dict = eval(strJson) # Now it is a dictionary
        dictionaryList.append(dict)
    return dictionaryList


def createCalledVulnerableFunctionList(vulnerableFunctionsDictionaryList, calledFunctionsList):
    calledVulnerableFunctionList = []
    notCalledVulnerableFunctions = []

    for dict in vulnerableFunctionsDictionaryList:
        for file in dict:
            removeDuplicates = set(dict[file])
            vulnerableFunctionsList = list(removeDuplicates)
            for funcIDX in range(len(vulnerableFunctionsList)):
                vulnerableFunction = vulnerableFunctionsList[funcIDX]
                if vulnerableFunction in calledFunctionsList:
                    calledVulnerableFunctionList.append(vulnerableFunction)
                else:
                    notCalledVulnerableFunctions.append(vulnerableFunction)
    
    return calledVulnerableFunctionList, notCalledVulnerableFunctions


def createCalledFunctionList(calledFunctionsDictionaryList):
    calledFunctionList = []
    for dict in calledFunctionsDictionaryList:
        for key in dict:
            if key == 'function_name':
                if "'" in dict[key]:
                    functionName = getCalledFunctionName(dict[key], "'") 
                elif "built-in" in dict[key]:
                    functionName = getCalledFunctionName(dict[key], " ") 
                elif "function " in dict[key]:
                    functionName = getCalledFunctionName(dict[key], " ") 
                else:
                    functionName = dict[key]
                calledFunctionList.append(functionName)
            
    return calledFunctionList



def loadDictionaries(filename):
    # Open the file
    with open(filename) as f:
        objectsList = f.readlines()

    # Convert the string to a list of dictionaries
    for i in range(len(objectsList)):
        try:
            objectsList[i] = json.loads(objectsList[i].replace("'", "\""))
        except json.JSONDecodeError:
            logging.info(f"Error decoding JSON for index {i}")

    #print("Objects list: ", objectsList)
    return objectsList



def createFinalArtifact(calledVulnerableFunctionList, notCalledVulnerableFunctions, banditObjectsList, filesAndFunctionNames):
    calledVulnerableFunctionObjects = []
    notCalledVulnerableFunctionObjects = []
    objectsForVulnerabilitiesOutsideFunctions = []
    # Iterate over dictionary keys
    for dict in filesAndFunctionNames:
        for key in dict:
            if dict[key] == []:
                tmp = {}
                tmp['line_number'] = []
                tmp['issue_text'] = []
                tmp['issue_severity'] = []
                tmp['issue_confidence'] = []
                tmp['issue_cwe'] = []
                tmp['more_info'] = []
                #print("No functions in file: ", key)
                for obj in banditObjectsList:
                    if key == obj['filename']:                   
                        tmp['filename'] = obj['filename']
                        tmp['line_number'].append(obj['line_number'])
                        tmp['issue_text'].append(obj['issue_text'])
                        tmp['issue_severity'].append(obj['issue_severity'])
                        tmp['issue_confidence'].append(obj['issue_confidence'])
                        tmp['issue_cwe'].append(obj['issue_cwe'])
                        tmp['more_info'].append(obj['more_info'])
                objectsForVulnerabilitiesOutsideFunctions.append(tmp)
            else:
                for function in dict[key]:
                    if function in calledVulnerableFunctionList:
                        tmp = {}
                        tmp['function'] = function
                        tmp['line_number'] = []
                        tmp['issue_text'] = []
                        tmp['issue_severity'] = []
                        tmp['issue_confidence'] = []
                        tmp['issue_cwe'] = []
                        tmp['more_info'] = []
                        for obj in banditObjectsList:
                            if key == obj['filename']: 
                                tmp['filename'] = obj['filename']
                                tmp['function'] = function
                                tmp['line_number'].append(obj['line_number'])
                                tmp['issue_text'].append(obj['issue_text'])
                                tmp['issue_severity'].append(obj['issue_severity'])
                                tmp['issue_confidence'].append(obj['issue_confidence'])
                                tmp['issue_cwe'].append(obj['issue_cwe'])
                                tmp['more_info'].append(obj['more_info'])
                        calledVulnerableFunctionObjects.append(tmp) # Duplicates
                    if function in notCalledVulnerableFunctions:
                        tmp = {}
                        tmp['function'] = function
                        tmp['line_number'] = []
                        tmp['issue_text'] = []
                        tmp['issue_severity'] = []
                        tmp['issue_confidence'] = []
                        tmp['issue_cwe'] = []
                        tmp['more_info'] = []
                        for obj in banditObjectsList:
                            if key == obj['filename']: 
                                tmp['filename'] = obj['filename']
                                tmp['function'] = function
                                tmp['line_number'].append(obj['line_number'])
                                tmp['issue_text'].append(obj['issue_text'])
                                tmp['issue_severity'].append(obj['issue_severity'])
                                tmp['issue_confidence'].append(obj['issue_confidence'])
                                tmp['issue_cwe'].append(obj['issue_cwe'])
                                tmp['more_info'].append(obj['more_info'])
                        notCalledVulnerableFunctionObjects.append(tmp)

    return calledVulnerableFunctionObjects, notCalledVulnerableFunctionObjects, objectsForVulnerabilitiesOutsideFunctions 



def saveArtifactsToFile(calledVulnerableFunctionsObjectList, notCalledVulnerableFunctionsObjectList, vulnerabilitiesOutsideFunctionsObjectList):
    with open('./app/artifacts/calledVulnerableFunctionsObjectList.txt', 'w') as f:
        for obj in calledVulnerableFunctionsObjectList:
            f.write(str(obj) + "\n")
    with open('./app/artifacts/notCalledVulnerableFunctionsObjectList.txt', 'w') as f:
        for obj in notCalledVulnerableFunctionsObjectList:
            f.write(str(obj) + "\n")
    with open('./app/artifacts/vulnerabilitiesOutsideFunctionsObjectList.txt', 'w') as f:
        for obj in vulnerabilitiesOutsideFunctionsObjectList:
            f.write(str(obj) + "\n")



def matchVulnerableFunctionsToCalledFunctions():
    vulnerableFunctionsList = getListFromFile('./app/artifacts/filesAndFunctionNames.txt')
    #print("Vulnerable functions list: ", vulnerableFunctionsList)
    calledFunctionsList = getListFromFile('./app/artifacts/profile_data.txt')
    #print("Called functions list: ", calledFunctionsList)

    vulnerableFunctionsDictionaryList = getDictionaryList(vulnerableFunctionsList)
    #print("Vulnerable functions dictionary list: ", vulnerableFunctionsDictionaryList)
    calledFunctionsDictionaryList = getDictionaryList(calledFunctionsList)
    #print("Called functions dictionary list: ", calledFunctionsDictionaryList)

    calledFunctionList = createCalledFunctionList(calledFunctionsDictionaryList)
    #print("Called function list: ", calledFunctionList)
    #print(len(calledFunctionList))

    calledVulnerableFunctionList, notCalledVulnerableFunctions = createCalledVulnerableFunctionList(vulnerableFunctionsDictionaryList, calledFunctionList)
    #print("Called vulnerable function list: ", calledVulnerableFunctionList)
    #print("Not called vulnerable functions: ", notCalledVulnerableFunctions)
    #print(len(calledVulnerableFunctionList))
    #print(len(notCalledVulnerableFunctions))

    banditObjectsList = loadDictionaries("./app/artifacts/banditObjects.txt")
    #print("Bandit objects list: ", banditObjectsList)
    filesAndFunctionNames = loadDictionaries("./app/artifacts/filesAndFunctionNames.txt")
    #print("Files and function names: ", filesAndFunctionNames)

    calledVulnerableFunctionsObjectList, notCalledVulnerableFunctionsObjectList, vulnerabilitiesOutsideFunctionsObjectList = createFinalArtifact(calledVulnerableFunctionList, notCalledVulnerableFunctions, banditObjectsList, filesAndFunctionNames)
    #print(calledVulnerableFunctionsObjectList)
    #print(notCalledVulnerableFunctionsObjectList)
    #print(vulnerabilitiesOutsideFunctionsObjectList)

    saveArtifactsToFile(calledVulnerableFunctionsObjectList, notCalledVulnerableFunctionsObjectList, vulnerabilitiesOutsideFunctionsObjectList)

if __name__ == "__main__":
    matchVulnerableFunctionsToCalledFunctions()