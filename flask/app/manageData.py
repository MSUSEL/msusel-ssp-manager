from flask import Blueprint, request, current_app as app, send_from_directory, jsonify, send_file, make_response
import os
import json
import logging
from typing import List, Dict, Tuple, Any
import ast
from .db_queries import DatabaseConnection, DatabaseQueryService
import networkx as nx
import traceback

logging.basicConfig(level=logging.INFO)
debugging = False

class ManageData:
    def __init__(self, cur_dir: str, db_query_service: DatabaseQueryService):
        self.cur_dir = cur_dir
        self.db_query_service = db_query_service
        self.security_findings_dictionary_list, self.implemented_controls_dictionary_list, self.vulnerable_functions = self.load_data()
        
        if debugging == True:
            logging.info(f"security_findings_dictionary_list: {self.security_findings_dictionary_list}")
            logging.info(f"implemented_controls_dictionary_list: {self.implemented_controls_dictionary_list}")
            logging.info(f"vulnerable_functions: {self.vulnerable_functions}")
            pass
        
        self.findings_list = self.createFindingsList(self.security_findings_dictionary_list) # ['78', '703', '605', '400', '319']
        
        if debugging == True:
            logging.info(f"findings_list: {self.findings_list}")
            pass
        
        self.finding_type = self.weaknessOrVulnerability() # Either 'cve' or 'cwe'
        self.cursor_techniques_and_findings = None # {'tech': 'technique/T1040', 'cwe': ['319']}, ...
        if self.finding_type == 'cve':
            self.cursor_techniques_and_findings = self.db_query_service.fetch_attacks_against_cves(self.findings_list)
        else:
            self.cursor_techniques_and_findings = self.db_query_service.fetch_attacks_against_cwes(self.findings_list)
            if debugging == True:
                #self.db_query_service.print_cursor(self.cursor_techniques_and_findings) # {'tech': 'technique/T1040', 'cwe': ['319']}, ...
                pass
        
        self.attackTechniquesUsableAgainstSecurityFindings = [] # ['technique/T1040', 'technique/T1056.004', 'technique/T1499']
        self.attackTechniqueIDsAndListOfMatchedFindings = [] # [['technique/T1040', ['319']], ['technique/T1056.004', ['319']], ['technique/T1499', ['400']]]
        
        # Fills attackTechniquesUsableAgainstSecurityFindings and attackTechniqueIDsAndListOfMatchedFindings
        self.populateHelperDataStructures()
        
        self.cursor_techniques_and_controls = self.db_query_service.fetch_priority_controls(self.attackTechniquesUsableAgainstSecurityFindings)
        '''{'tech_id': 'technique/T1040', 
        'tech_name': 'Network Sniffing', 
        'ctrl': ['CM-07 (Least Functionality)', 'AC-16 (Security and Privacy Attributes)', 'AC-17 (Remote Access)', 
        'AC-18 (Wireless Access)', 'AC-19 (Access Control for Mobile Devices)', '
        IA-02 (Identification and Authentication (organizational Users))', 'IA-05 (Authenticator Management)', 
        'SC-04 (Information in Shared System Resources)', 'SC-08 (Transmission Confidentiality and Integrity)', 
        'SI-12 (Information Management and Retention)', 'SI-04 (System Monitoring)', 
        'SI-07 (Software, Firmware, and Information Integrity)']}'''
        if debugging == True:
            #self.db_query_service.print_cursor(self.cursor_techniques_and_controls)  
            pass
        
        
        self.recommendationsTableData = []
        self.buildRecommendationsTableData(self.cursor_techniques_and_controls)
        if debugging == True:
            logging.info(f"Recommendations Table Data: {self.recommendationsTableData}")
            '''INFO:root:Recommendations Table Data: 
            [{'cwe': ['319'], 'Technique ID': 'technique/T1040', 'Technique Name': 'Network Sniffing', 'Control (Name)': ['CM-07 (Least Functionality)', 'AC-16 (Security and Privacy Attributes)', 'AC-17 (Remote Access)', 'AC-18 (Wireless Access)', 'AC-19 (Access Control for Mobile Devices)', 'IA-02 (Identification and Authentication (organizational Users))', 'IA-05 (Authenticator Management)', 'SC-04 (Information in Shared System Resources)', 'SC-08 (Transmission Confidentiality and Integrity)', 'SI-12 (Information Management and Retention)', 'SI-04 (System Monitoring)', 'SI-07 (Software, Firmware, and Information Integrity)']}, 
            {'cwe': ['400'], 'Technique ID': 'technique/T1499', 'Technique Name': 'Endpoint Denial of Service', 'Control (Name)': ['AC-03 (Access Enforcement)', 'AC-04 (Information Flow Enforcement)', 'CA-07 (Continuous Monitoring)', 'CM-06 (Configuration Settings)', 'CM-07 (Least Functionality)', 'SC-07 (Boundary Protection)', 'SI-10 (Information Input Validation)', 'SI-15 (Information Output Filtering)', 'SI-04 (System Monitoring)']}]'''
            pass
        
        self.cursor_tactic_to_technique = self.db_query_service.fetch_tactics_to_techniques(self.attackTechniquesUsableAgainstSecurityFindings)
        # {'From': 'tactic/TA0002', 'To': 'technique/T1040'}, ...
        if debugging == True:
            #self.db_query_service.print_cursor(self.cursor_tactic_to_technique) # {'From': 'tactic/TA0002', 'To': 'technique/T1040'}, ...
            pass
        
        self.tacticsList = [] # ['tactic/TA0006', ...]
        self.tacticsAndTechniquesGraph = nx.Graph()
        # Nodes: ['tactic/TA0002', 'technique/T1040', ...]
        # Edges: [('tactic/TA0002', 'technique/T1040'), ...]
        
        # It is used to find the prioriti tactic in the colorPriorityStage method.
        # The stage in the middle of the path that has the least amount of techniques to neutralize.
        self.tacticsOnlyGraph = nx.DiGraph()
        '''Nodes in the tactics only graph:  ['tactic/tactic_00003', 'tactic/tactic_00005']
        Edges in the tactics only graph: [('tactic/tactic_00003', 'tactic/tactic_00005')]'''

        
        self.user_priority_BRONtacticID = None
        if debugging == True:
            logging.info("Initialized user_priority_BROBtacticID attribute.")

        self.addNodesAndEdgesBetweenTacticsAndTechniques(self.cursor_tactic_to_technique)

        # Remove duplicates from the list of tactics
        self.tacticsList = list(set(self.tacticsList))

        self.tacticsOriginalIDsList = [item.split('/')[1] for item in self.tacticsList]
        if debugging == True:
            logging.info(f"tacticsOriginalIDsList: {self.tacticsOriginalIDsList}")
            pass

        self.cursor_arangodb_tactic_id = self.db_query_service.fetch_tactic_id(self.tacticsOriginalIDsList)
        if debugging == True:
            #logging.info(f"Printing cursor_arangodb_tactic_id: {type(self.cursor_arangodb_tactic_id)}")
            #self.db_query_service.print_cursor(self.cursor_arangodb_tactic_id) # tactic/TA0006, ...
            pass
        
        self.arangodb_tactic_id_list = self.createListFromCursor(self.cursor_arangodb_tactic_id)
        if debugging == True:
            logging.info(f"arangodb_tactic_id_list: {self.arangodb_tactic_id_list}") # ['tactic/TA0006', 'tactic/TA0005', 'tactic/TA0007', 'tactic/TA0008', 'tactic/TA0003', 'tactic/TA0004', 'tactic/TA0043']
            pass     

        self.addEdgesBetweenTacticsToGraphs(self.db_query_service.db_connection.tacticToTacticEdgeCollection)
        
        self.user_priority_BRONtacticID = ''
        self.priority_list = self.colorPriorityNode(self.user_priority_BRONtacticID)
        '''Priority list: [('tactic/TA0007', 1), ('tactic/TA0009', 1), ('tactic/TA0040', 1), ('tactic/TA0006', 2)]
        Tactic/original_id, NumberOfTechniques that execute the tactic.'''
        if debugging == True:
            logging.info(f"Priority list: {self.priority_list}")
            pass

        self.priority_controls_table_data = self.create_table(self.db_query_service, self.priority_list, self.recommendationsTableData)

        self.json_priority_controls_table_data = self.createJSONFromDictList(self.priority_controls_table_data)
        if debugging == True:
            logging.info(f"JSON Priority Controls Table Data: {self.json_priority_controls_table_data}")
            pass
       
        # Assuming tacticsOnlyGraph.nodes is an iterable (e.g., dict_keys or similar)
        listOfTactics = list(self.tacticsOnlyGraph.nodes)
        self.orderedTacticsPathOriginalIDs = []
        #For each item in the list of tactics, run the fetch_original_id method.
        for tactic in listOfTactics:
            cursor = self.db_query_service.fetch_original_tacticID(tactic)
            # Extract value from the cursor and append it to the list of tactic original IDs.
            for doc in cursor:
                self.orderedTacticsPathOriginalIDs.append(doc)  
        
        if debugging == True:
            logging.info(f"List of tactic original IDs: {self.orderedTacticsPathOriginalIDs}")
            pass
        #logging.info(f"List of tactic original IDs: {self.orderedTacticsPathOriginalIDs}")


    # Method returns three lists of dictionaries.
    def load_data(self) ->  Tuple[List[Dict[str, str]], List[Dict[str, str]], List[Dict[str, str]]]:
        """Load input data from JSON files."""
        security_findings_path = os.path.join(self.cur_dir, "shared", 'vulnerabilities.json')
        implemented_controls_path = os.path.join(self.cur_dir, "shared", 'controls.json')
        vulnerable_functions_path = os.path.join(self.cur_dir, "app/artifacts", 'calledVulnerableFunctionsObjectList.txt')
    

        with open(security_findings_path, 'r') as f:
            security_findings = json.load(f)
        with open(implemented_controls_path, 'r') as f:
            implemented_controls = json.load(f)
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

        return security_findings, implemented_controls, vulnerable_functions


    def weaknessOrVulnerability(self):
        if debugging == True:
            logging.info("Enterred weaknessOrVulnerability method. This method determines whether the input json file contains a list of weaknesses (cwe) or vulnerabilities (cve).")
            pass
        
        is_cveList = self.security_findings_dictionary_list[0].get('cve', None)
        if debugging == True:
            logging.info(f"Get the value of the 'cve' key from the first item in the security_findings_dictionary_list: {is_cveList}. If it is not None, the input json file contains a list of weaknesses.")
            pass
        
        is_cweList = self.security_findings_dictionary_list[0].get('cwe', None)
        if debugging == True:
            logging.info(f"Get the value of the 'cwe' key from the first item in the security_findings_dictionary_list: {is_cweList}. If it is not None, the input json file contains a list of vulnerabilities.")
            pass

        if is_cveList is not None: 
            logging.info('CVE list detected') 
            return 'cve'
        elif is_cweList is not None: 
            logging.info('CWE list detected')
            return 'cwe'
        else:
            print('Invalid (not \'cve\'/\'cwe\') item detected from the input json file')


    def createFindingsList(self, security_findings_dictionary_list):
        if debugging == True:
            logging.info("Enterred createFindingsList method.")
            pass
        findings_list = []

        if debugging == True:
            logging.info("Declared findings_list local variable.")
            logging.info("Iterating through the security_findings_dictionary_list. For each dictionary in the list, we will append the value to the findings_list.")
            pass
        
        for dict in security_findings_dictionary_list:
            for value in dict.values():
                findings_list.append(value)

        if debugging == True:
            logging.info(f"Finished iterating through the security_findings_dictionary_list. Findings list: {findings_list}")
            logging.info("Will return findings_list.")  
            pass

        return findings_list 
    
    def createListFromCursor(self, cursor):
        if debugging == True:
            logging.info("Enterred createListFromCursor method.")
            logging.info("Will iterate through the cursor. For each dictionary in the cursor, we will append the dictionary to the list.")
            pass
        
        list = []
        for dict in cursor:
            list.append(dict)
        
        if debugging == True:
            logging.info(f"Finished iterating through the cursor. List: {list}")
            logging.info("Will return list.")
            pass
        return list


    def createJSONFromDictList(self, dict_list):
        my_dict = {}
        for d in dict_list:
            for k, v in d.items():
                my_dict[k] = v
        return my_dict



    # Modified: where not doing this right now.
    # This method is used to populate the attackTechniquesUsableAgainstSecurityFindings and attackTechniqueIDsAndListOfMatchedFindings lists.
    # The cursor_techniques_and_findings is a list of dictionaries. Each dictionary contains a key 'tech' and a key 'cwe' or 'cve'.=> {'tech': 'technique/T1040', 'cwe': ['319']}, ...
    # This methods checks if the controls that can mitigate the attack techniques are implemented. 
    # For each technique, the controls that can mitigate the technique are stored in the controlsToMitigateTechniques list (we iterate through the techniqueControlCollection).
    # If the controls are NOT implemented, the technique is added to the attackTechniquesUsableAgainstSecurityFindings list.
    def populateHelperDataStructures(self):
        if debugging == True:
            logging.info("Enterred populateHelperDataStructures method.")
            logging.info("Will iterate through the cursor_techniques_and_findings. For each techniqueFinding dictionary in the cursor, we will extract the values and store them in a list.")
            pass
        if debugging == True:
            #self.db_query_service.print_cursor(self.cursor_techniques_and_findings) 
            pass
        
        for singleTechniqueFindingDictionary in self.cursor_techniques_and_findings:
            if debugging == True:
                logging.info(f"Element in cursor is Single technique finding dictionary: {singleTechniqueFindingDictionary}")
                pass
            
            controlsToMitigateTechniques = [] # stores controls that map to the current attack technique
            if debugging == True:
                logging.info("Declared controlsToMitigateTechniques list.")
                pass
            
            techniquesAndFindingsList = list(singleTechniqueFindingDictionary.values())
            if debugging == True:
                logging.info(f"Created list from the singleTechniqueFindingDictionary. Techniques and findings list: {techniquesAndFindingsList}")
                pass
            techniqueMappedToFinding = techniquesAndFindingsList[0]
            if debugging == True:
                logging.info(f"Get the technique mapped to finding: {techniqueMappedToFinding}")
                pass
            
            if debugging == True:
                logging.info("Will check if the technique mapped to the finding is not in the attackTechniquesUsableAgainstSecurityFindings list.")
            
            # Check if the technique has not been added to the attackTechniquesUsableAgainstSecurityFindings list.
            if techniqueMappedToFinding not in self.attackTechniquesUsableAgainstSecurityFindings:
                if debugging == True:
                    logging.info(f"Technique {techniqueMappedToFinding} not in attackTechniquesUsableAgainstSecurityFindings list.")
                    pass
                
                # Iterate through the techniqueControlCollection to get the controls that can mitigate the technique.
                for techniqueControlEdge in self.db_query_service.db_connection.techniqueControlCollection: # {'_from': 'technique/T1040', '_to': 'control/CM-07'}, ...
                    if techniqueControlEdge['_from'] == techniqueMappedToFinding:
                        controlsToMitigateTechniques.append(techniqueControlEdge['_to'])
                        if debugging == True:
                            logging.info(f"To mitigate technique {techniqueMappedToFinding}, added control to controlsToMitigateTechniques: {techniqueControlEdge['_to']}. Will soon check if this control is implemented.")
                
                if debugging == True:
                    logging.info(f"Controls to mitigate techniques: {controlsToMitigateTechniques}")
                
                self.attackTechniquesUsableAgainstSecurityFindings.append(techniqueMappedToFinding)
                self.attackTechniqueIDsAndListOfMatchedFindings.append(techniquesAndFindingsList)
                
        if debugging == True:
            logging.info(f"Attack techniques usable against security findings: {self.attackTechniquesUsableAgainstSecurityFindings}")
            logging.info("")
            logging.info(f"Attack technique IDs and list of matched findings: {self.attackTechniqueIDsAndListOfMatchedFindings}")
            logging.info("")
            logging.info("Will return attackTechniquesUsableAgainstSecurityFindings and attackTechniqueIDsAndListOfMatchedFindings.")

        return self.attackTechniquesUsableAgainstSecurityFindings,self.attackTechniqueIDsAndListOfMatchedFindings

    def buildRecommendationsTableData(self, cursorTechniquesAndControls):
        if debugging == True:
            logging.info("Enterred buildRecommendationsTableData method.")
            logging.info("Will iterate through the cursorTechniquesAndControls. For each techniqueControl dictionary in the cursor, we will extract the values and store them in a list.")
            logging.info("For each techniqueControl dictionary, we will get the tech_id")
            logging.info("We will also iterate through the attackTechniqueIDsAndListOfMatchedFindings. For each techniqueAndFindingsList in the list, we will check if the technique ID is equal to the tech_id in the techniqueControl dictionary.")
            pass
        
        for techniqueControlDict in cursorTechniquesAndControls:
            tech_id = techniqueControlDict['tech_id']
            for techniqueAndFindingsList in self.attackTechniqueIDsAndListOfMatchedFindings:
                if debugging == True:
                    logging.info(f"techniqueAndFindingsList in attackTechniqueIDsAndListOfMatchedFindings: {techniqueAndFindingsList}")
                    logging.info("Will check if the tech_id is equal to the techniqueAndFindingsList[0].")
                
                if tech_id == techniqueAndFindingsList[0]:
                    finding = 'cwe'
                    if 'cve' in techniqueAndFindingsList[1][0].lower():
                            finding = 'cve'
                    if debugging == True:
                        logging.info(f"Will create table item with the following values: {finding}, {tech_id}, {techniqueControlDict['tech_name']}")
                    table_item = {finding: techniqueAndFindingsList[1],'Technique ID': tech_id, 'Technique Name': techniqueControlDict['tech_name']} 
                    
                    if debugging == True:
                        logging.info(f"Will add the control to the table item: {techniqueControlDict['ctrl']}")
                    table_item = table_item | {'Control (Name)': techniqueControlDict['ctrl']}
                    
                    if debugging == True:
                        logging.info(f"Table item: {table_item}")
                        logging.info("Will append the table item to the self.recommendationsTableData list.")
                    self.recommendationsTableData.append(table_item)


    def addNodesAndEdgesBetweenTacticsAndTechniques(self, cursorTacticToTechnique):
        if debugging == True:
            logging.info("Enterred addNodesAndEdgesBetweenTacticsAndTechniques method.")
            logging.info("Will iterate through the cursorTacticToTechnique. For each edge in the cursor, we will extract the items and add them to the tacticsAndTechniquesGraph.")
            pass
        
        for edge in cursorTacticToTechnique:
            if debugging == True:
                logging.info(f"Edge: {edge}")
            tactic, technique = edge.items() # Tactic: ('From', 'tactic/TA0006'), Technique: ('To', 'technique/T1040')
            
            if debugging == True:
                logging.info(f"From edge.items() we get: Tactic: {tactic}, Technique: {technique}")
                logging.info("adding nodes and edges to tactics and techniques graph")
                logging.info(f"The nodes are: {tactic[1]}, {technique[1]}")
                pass
            
            self.tacticsAndTechniquesGraph.add_nodes_from([tactic[1], technique[1]])

            if debugging == True:
                logging.info("Nodes added to tactics and techniques graph.")
                logging.info("adding edges to tactics and techniques graph")
                logging.info(f"Adding edge to tacticsAndTechniquesGraph: {tactic[1]} -> {technique[1]}")


            self.tacticsAndTechniquesGraph.add_edge(tactic[1], technique[1])
            if debugging == True:
                logging.info("Edge added to tactics and techniques graph.")
                logging.info(f"Adding tactic to tacticsList: {tactic[1]}")
                pass
            
            self.tacticsList.append(tactic[1])
            if debugging == True:
                logging.info("Tactic added to tacticsList.")
        
        if debugging == True:
            logging.info("")
            logging.info("Finished adding nodes in the tactics and techniques graph: ")
            logging.info(f"Nodes in the tactics and techniques graph: {self.tacticsAndTechniquesGraph.nodes}")

            logging.info("")
            logging.info("Edges in the tactics and techniques graph: ")
            logging.info(f"Edges in the tactics and techniques graph: {self.tacticsAndTechniquesGraph.edges}")

            logging.info("")
            logging.info("Tactics list: ")
            logging.info(f"Tactics list: {self.tacticsList}")


    def addEdgesBetweenTacticsToGraphs(self, tacticToTacticEdgeCollection):
        if debugging == True:
            logging.info("Enterred addEdgesBetweenTacticsToGraphs method.")
            logging.info("Will iterate through the tacticToTacticEdgeCollection. For each edge in the collection, we will extract the items and add them to the tacticsAndTechniquesGraph.")
            pass
        
        for edge in tacticToTacticEdgeCollection:
            if debugging == True:
                logging.info("adding edges to tactics and techniques graph")
                logging.info(f"Edge: {edge}")
                logging.info("Checking if edge['_from'] and edge['_to'] are in the tactics list.")
                logging.info(f"tacticsList: {self.tacticsList}")
                pass
           
            if edge['_from'] in self.arangodb_tactic_id_list and edge['_to'] in self.arangodb_tactic_id_list: # Never true?
                if debugging == True:
                    logging.info("")
                    logging.info("Edge in tactics list true")
                    logging.info("")
                try:
                    if debugging == True:
                        logging.info(f"Adding edge to tacticsAndTechniquesGraph: {edge['_from']} -> {edge['_to']}")
                    
                    self.tacticsAndTechniquesGraph.add_edge(edge['_from'], edge['_to'])
                    if debugging == True:
                        logging.info(f"Successfully added edge to tacticsAndTechniquesGraph: {edge['_from']} -> {edge['_to']}")
                except Exception as e:
                    logging.error(f"Error adding edge to tacticsAndTechniquesGraph: {e}")
                    logging.error(traceback.format_exc())

                try:
                    if debugging == True:
                        logging.info(f"Adding edge to tacticsOnlyGraph: {edge['_from']} -> {edge['_to']}")
                    self.tacticsOnlyGraph.add_edge(edge['_from'], edge['_to'])
                    if debugging == True:
                        logging.info(f"Successfully added edge to tacticsOnlyGraph: {edge['_from']} -> {edge['_to']}")
                except Exception as e:
                    logging.info(f"Error adding edge to tacticsOnlyGraph: {e}")
        if debugging == True:
            logging.info(f"Nodes in the tactics only graph:  {self.tacticsOnlyGraph.nodes}")      
            logging.info(f"Edges in the tacticsAndTechniquesGraph: {self.tacticsAndTechniquesGraph.edges}")
            logging.info(f"Neighbors in the tacticsAndTechniquesGraph: {self.tacticsAndTechniquesGraph.neighbors}")


    def sortPriorityTactics(self, a_list):
        return sorted(a_list, key=lambda tup: tup[1], reverse=False)
    
    # finds priority of tactic
    def colorPriorityNode(self, user_priority_BRONtacticID):
        if debugging == True:
            logging.info("Enterred colorPriorityNode method.")
        # priority of tactic
        high = []
        mid = []
        low = []

        # iterate over every node in the graph
        for node in self.tacticsAndTechniquesGraph.__iter__():
            if debugging == True:
                logging.info(f"Node: {node}")
            # Nodes: ['tactic/TA0002', 'technique/T1040', ...]
            # Edges: [('tactic/TA0002', 'technique/T1040'), ...]
            '''Node: tactic/TA0006
            :Node: technique/T1040
            ...'''
            # if its a tactic node
            if 'tactic' in node:
                if debugging == True:
                    logging.info(f"Node is a tactic: {node}")
                    pass
                
                
                # start the edge type counters
                cnt_tac = 0
                cnt_tech = 0

                # if the tactic is the one that user specified, prioritize the node
                '''if user_priority_BRONtacticID != None and user_priority_BRONtacticID in node:
                    high.append((node, 0))
                    f = open('/shared/debug_input.txt', 'a')
                    f.write('User selected tactic: ' + user_priority_BRONtacticID + '\n') # This works
                    f.close()
                else:'''
                for neighbor in self.tacticsAndTechniquesGraph.neighbors(node):
                    if debugging == True:
                        logging.info(f"Neighbor: {neighbor}")
                    if 'technique' in neighbor:
                            # add a technique edge
                        cnt_tech += 1
                    else:
                            # add a tactic edge
                        cnt_tac += 1
                    # sort the nodes into high, mid, and low priority based on tactic to tactic connectivity
                match cnt_tac:
                    case 0:
                        if debugging == True:
                            logging.info(f"Case 0: {node}, neighboring tactics: {cnt_tac}, negihboring techniques: {cnt_tech}")
                        if cnt_tech != 0:
                            low.append((node, cnt_tech))
                    case 1:
                        if debugging == True:
                            logging.info(f"Case 1: {node}, neighboring tactics: {cnt_tac}, negihboring techniques: {cnt_tech}")
                        if cnt_tech != 0:
                            mid.append((node, cnt_tech))
                    case _:
                        if debugging == True:
                            logging.info(f"Case 0: {node}, neighboring tactics: {cnt_tac}, negihboring techniques: {cnt_tech}")
                        if cnt_tech != 0:
                            high.append((node, cnt_tech))
     
        # sort the individual lists
        low = self.sortPriorityTactics(low)
        mid = self.sortPriorityTactics(mid)
        high = self.sortPriorityTactics(high)


        # determine the highest priority node and change color to red
        # We want the tactic with the least amount of techniques to neutralize
        print('Low:', low, "\nMid:", mid, "\nHigh:", high)
        if debugging == True:  
            logging.info(f"Low: {low}, Mid: {mid}, High: {high}")
        if high.__len__() > 0 and self.tacticsAndTechniquesGraph.has_node(high[0][0]):
            print(f"Coloring tactic red: {high[0][0]}")
            logging.info(f"Coloring tactic red: {high[0][0]}")
            self.tacticsAndTechniquesGraph.add_node(high[0][0], color='red')
        elif mid.__len__() > 0 and self.tacticsAndTechniquesGraph.has_node(mid[0][0]):
            print(f"Coloring tactic red: {mid[0][0]}")
            logging.info(f"Coloring tactic red: {mid[0][0]}")
            self.tacticsAndTechniquesGraph.add_node(mid[0][0], color='red')
        elif low.__len__() > 0 and self.tacticsAndTechniquesGraph.has_node(low[0][0]):
            print(f"Coloring tactic red: {low[0][0]}")
            logging.info(f"Coloring tactic red: {low[0][0]}")
            self.tacticsAndTechniquesGraph.add_node(low[0][0], color='red')
        else:
            pass

        # returns a list that has all prioritize lists
        return high + mid + low



    def create_table(self, db, prioritize_lists, recommendationsTableData):
        if debugging == True:
            logging.info("Enterred create_table method.")
        table_list = [] # will contain data for each table entry

        if debugging == True:
            logging.info("Declared table_list local variable.")
            # loop to find the technique that maps to the specific tactic
            logging.info("Will iterate through the prioritize_lists. For each item in the list, we will find the technique(s) that map from the specific tactic.")
            '''Priority list: [('tactic/TA0007', 1), ('tactic/TA0009', 1), ('tactic/TA0040', 1), ('tactic/TA0006', 2)]
            Tactic/original_id, NumberOfTechniques that execute the tactic.'''
        
        
        for obj in prioritize_lists:
            if debugging == True:
                logging.info(f"Item in prioritize_lists: {obj}")
            tactic_id = obj[0] # obj -> ('tactic/tactic_00008', 0), for ex

            if debugging == True:
                logging.info(f"Tactic ID extracted from obj: {tactic_id}")
            cursor = self.db_query_service.fetch_technique_id(tactic_id)

            # checks whether the technique is in the graph
            if debugging == True:
                logging.info("Will iterate through the cursor. For each technique in the cursor, we will check if it is in the tacticsAndTechniquesGraph.")
            for tech_id in cursor:
                if debugging == True:
                    logging.info(f"Technique ID: {tech_id}")
                    logging.info("Will iterate through the recommendationsTableData. For each item in the list, we will check if the technique ID is in the item.")
                for data in recommendationsTableData:
                    if debugging == True:
                        logging.info(f"Item in recommendationsTableData: {data}")
                    if tech_id == data['Technique ID']:
                        if debugging == True:
                            logging.info("Technique ID found in the recommendationsTableData.")
                            logging.info("Will execute a query to get the tactic name.")
                        
                        cursor_tac = self.db_query_service.fetch_tactic_name(tactic_id)
                        if debugging == True:
                            logging.info("Returned from the query execution. Back in create_table method.")
                        
                        tactic = tactic_id + ' (' + next(cursor_tac) + ')'
                        if debugging == True:
                            logging.info(f"Tactic: {tactic}")
                            logging.info("Will append the tactic and data to the table_list.")
                        table_list.append({tactic:data})
                        break
        if debugging == True:
            logging.info("Returned from the loop. Back in create_table method.")
            pass

        # convert the table_list to a json object and return it
        if debugging == True:
            logging.info(f"Table list: {table_list}")
            logging.info("Will return table_list.")
            pass
        
        return table_list


