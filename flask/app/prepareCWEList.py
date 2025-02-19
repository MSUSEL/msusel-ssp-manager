# This programs reads the calledVulnerableFunctionsObjectList.txt file.
# The calledVulnerableFunctionsObjectList.txt contains a list of dictionaries.
# Each dictionary contains a 'issue_cwe' key which has as values a list of dictionaries.
# Each dictionary in the list has a 'id' key. 
# This program reads the calledVulnerableFunctionsObjectList.txt
# and creates a list of dictionaries where each key is "cwe" and 
# the values is the value for the 'id' key.
import json
import sys
import logging

logging.basicConfig(level=logging.INFO)

def createDictList(filename):
    with open(filename, 'r') as file:
        dict_list = []
        for line in file:
            # Fix the JSON object by adding double quotes around property names
            fixed_line = line.replace("'", "\"")
            dict_list.append(json.loads(fixed_line))
    file.close()
    return dict_list

def createCWEList(dict_list):
    cweList = []
    for obj in dict_list:
        tmp = {}
        for cweObject in obj['issue_cwe']:
            tmp['cwe'] = str(cweObject['id'])
            cweList.append(tmp)
    return cweList

def removeDuplicates(cweList):
    return [dict(t) for t in {tuple(d.items()) for d in cweList}]

def prepareCWEList():
    dict_list = createDictList('./app/artifacts/calledVulnerableFunctionsObjectList.txt')
    logging.info(f"dict_list: {dict_list}")
    cweList = createCWEList(dict_list)
    logging.info(f"cweList: {cweList}")
    cweList = removeDuplicates(cweList)
    logging.info(f"cweList: {cweList}")

    dict_list = createDictList('./app/artifacts/vulnerabilitiesOutsideFunctionsObjectList.txt')
    logging.info(f"dict_list: {dict_list}")
    cweList += createCWEList(dict_list)
    logging.info(f"cweList: {cweList}")
    cweList = removeDuplicates(cweList)
    logging.info(f"cweList: {cweList}")

    with open('/shared/vulnerabilities.json', 'w') as file:
        file.write(json.dumps(cweList))

if __name__ == "__main__":
    prepareCWEList()
    sys.exit(0)