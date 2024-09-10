import json

def parseBandit():
    with open('./app/artifacts/bandit_output_test.json') as f:
        banditOutputDictionary = json.load(f)

    fileAndVulnerabilitiesLinesDictionaryList = []

    # Extract the filename and the line_number values from the json file
    for i in range(len(banditOutputDictionary['results'])):
        tmp = {}
        if 'test' in banditOutputDictionary['results'][i]['filename']: 
            continue
        tmp[banditOutputDictionary['results'][i]['filename']] = banditOutputDictionary['results'][i]['line_number']
        fileAndVulnerabilitiesLinesDictionaryList.append(tmp) 

    # Close the json file
    f.close()

    # Write list to file
    with open('./app/artifacts/fileAndVulnerabilitiesLinesDictionaryList.txt', 'w') as f:
        for item in fileAndVulnerabilitiesLinesDictionaryList:
            f.write("%s\n" % item)
    f.close()

    banditObjectsList = []

    for i in range(len(banditOutputDictionary['results'])):
        temp = {}
        if 'test' in banditOutputDictionary['results'][i]['filename']: 
            continue
        temp['filename'] = banditOutputDictionary['results'][i]['filename']
        temp['line_number'] = banditOutputDictionary['results'][i]['line_number']
        temp['issue_cwe'] = banditOutputDictionary['results'][i]['issue_cwe']
        temp['issue_severity'] = banditOutputDictionary['results'][i]['issue_severity']
        temp['issue_confidence'] = banditOutputDictionary['results'][i]['issue_confidence']
        temp['issue_text'] = banditOutputDictionary['results'][i]['issue_text']
        temp['more_info'] = banditOutputDictionary['results'][i]['more_info']
        banditObjectsList.append(temp)

    # Close the json file
    f.close()

    # Write list to file
    with open('./app/artifacts/banditObjects.txt', 'w') as f:
        for item in banditObjectsList:
            f.write("%s\n" % item)
    f.close()


if __name__ == '__main__':
    parseBandit()