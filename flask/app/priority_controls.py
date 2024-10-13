# Important: cursors can only be iterated on once. 
# If you want to iterate on the cursor multiple times, you need to store the results in a list.
from flask import Blueprint, request, current_app as app, send_from_directory, jsonify, send_file, make_response
import os
import json
import logging
from typing import List, Dict, Tuple, Any
import ast
from .db_queries import DatabaseConnection, DatabaseQueryService
import networkx as nx
from pyvis import network as net
import traceback

logging.basicConfig(level=logging.INFO)
debugging = True

priority_blueprint = Blueprint('priority', __name__)

class ManageData:
    def __init__(self, cur_dir: str, db_query_service: DatabaseQueryService):
        self.cur_dir = cur_dir
        self.db_query_service = db_query_service
        self.security_findings_dictionary_list, self.implemented_controls_dictionary_list, self.vulnerable_functions = self.load_data()
        if debugging == True:
            #logging.info(f"security_findings_dictionary_list: {self.security_findings_dictionary_list}")
            #logging.info(f"implemented_controls_dictionary_list: {self.implemented_controls_dictionary_list}")
            #logging.info(f"vulnerable_functions: {self.vulnerable_functions}")
            pass
        
        self.findings_list = self.createFindingsList(self.security_findings_dictionary_list) # ['78', '703', '605', '400', '319']
        if debugging == True:
            logging.info(f"findings_list: {self.findings_list}")
        self.cursor_techniques_and_findings = None # {'tech': 'technique/T1040', 'cwe': ['319']}, ...
        self.finding_type = self.weaknessOrVulnerability()
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
        self.determineAttackTechniquesNotMitigated()
        
        self.cursor_techniques_and_controls = self.db_query_service.fetch_priority_controls(self.attackTechniquesUsableAgainstSecurityFindings)
        #logging.info("Printing cursor_techniques_and_controls:")
        # Prints dictionaries where each dictionary has tech_id, tech_name, and ctrl list
        '''{'tech_id': 'technique/T1040', 
        'tech_name': 'Network Sniffing', 
        'ctrl': ['CM-07 (Least Functionality)', 'AC-16 (Security and Privacy Attributes)', 'AC-17 (Remote Access)', 
        'AC-18 (Wireless Access)', 'AC-19 (Access Control for Mobile Devices)', '
        IA-02 (Identification and Authentication (organizational Users))', 'IA-05 (Authenticator Management)', 
        'SC-04 (Information in Shared System Resources)', 'SC-08 (Transmission Confidentiality and Integrity)', 
        'SI-12 (Information Management and Retention)', 'SI-04 (System Monitoring)', 
        'SI-07 (Software, Firmware, and Information Integrity)']}'''
        #self.db_query_service.print_cursor(self.cursor_techniques_and_controls)  
        #logging.info("Returned from print_cursor method.")
        
        
        self.jsonTechniquesAndControls = None # Can't run get_techniques method, will empty the cursor.
        #self.jsonTechniquesAndControls = self.db_query_service.get_techniques(self.cursor_techniques_and_controls) 
        #self.db_query_service.print_cursor(self.cursor_techniques_and_controls) 
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
        logging.info("Declared tacticsList attribute")
        self.tacticsAndTechniquesGraph = nx.Graph()
        # Nodes: ['tactic/TA0002', 'technique/T1040', ...]
        # Edges: [('tactic/TA0002', 'technique/T1040'), ...]

        logging.info("Initialized tacticsAndTechniquesGraph. This is a networkx graph.")
        
        
        # This graph is not for a complete viasualization.
        # It is used to find the prioriti tactic in the show_prioritization method.
        # The stage in the middle of the path that has the least amount of techniques to neutralize.
        self.tacticsOnlyGraph = nx.DiGraph()
        '''Nodes in the tactics only graph:  ['tactic/tactic_00003', 'tactic/tactic_00005']
        Edges in the tactics only graph: [('tactic/tactic_00003', 'tactic/tactic_00005')]'''


        logging.info("Initialized tacticsOnlyGraph attribute. This is a networkx digraph.")
        self.pyvisTacticsAndTechniquesGraph = net.Network(height='100vh', width='100%', notebook=True, bgcolor="#FFFFFF", font_color="black")
        logging.info("Initialized pyvisTacticsAndTechniquesGraph attribute. This is a pyvis network object.")
        self.pyvisAttackPathsGraph = net.Network(height='100vh', width='100%', notebook=True, bgcolor="#FFFFFF", font_color="black")
        logging.info("Initialized pyvisAttackPathsGraph attribute. This is a pyvis network object.")
        self.user_priority_BRONtacticID = None
        logging.info("Initialized user_priority_BROBtacticID attribute.")

        self.addNodesAndEdgesToTacticsAndTechniquesGraph(self.cursor_tactic_to_technique)
        self.tacticsOriginalIDsList = [item.split('/')[1] for item in self.tacticsList]
        logging.info(f"tacticsOriginalIDsList: {self.tacticsOriginalIDsList}")

        self.cursor_tactic_id = self.db_query_service.fetch_tactic_id(self.tacticsOriginalIDsList)
        logging.info(f"Printing cursor_tactic_id: {type(self.cursor_tactic_id)}")
        if debugging == True:
            #self.db_query_service.print_cursor(self.cursor_tactic_id) 
            pass
        self.tactic_original_id_list = self.createListFromCursor(self.cursor_tactic_id)
        if debugging == True:
            #logging.info(f"tactic_original_id_list: {self.tactic_original_id_list}")
            pass

        self.addEdgesToTacticsAndTechniquesGraph(self.db_query_service.db_connection.tacticToTacticEdgeCollection)

        self.user_priority_BRONtacticID = ''
        self.priority_list = self.show_prioritize(self.user_priority_BRONtacticID)
        '''Low: [], Mid: [], High: [('tactic/TA0006', 0), ('tactic/TA0007', 0), ('tactic/TA0009', 0), ('tactic/TA0040', 0)]
        Priority list: [('tactic/TA0006', 0), ('tactic/TA0007', 0), ('tactic/TA0009', 0), ('tactic/TA0040', 0)]
        We have to fix the logic.
        '''
        if debugging == True:
            logging.info(f"Priority list: {self.priority_list}")
            pass

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
        logging.info("Enterred weaknessOrVulnerability method. This method determines whether the input json file contains a list of weaknesses (cwe) or vulnerabilities (cve).")
        is_cveList = self.security_findings_dictionary_list[0].get('cve', None)
        logging.info(f"Get the value of the 'cve' key from the first item in the security_findings_dictionary_list: {is_cveList}. If it is not None, the input json file contains a list of weaknesses.")
        is_cweList = self.security_findings_dictionary_list[0].get('cwe', None)
        logging.info(f"Get the value of the 'cwe' key from the first item in the security_findings_dictionary_list: {is_cweList}. If it is not None, the input json file contains a list of vulnerabilities.")
        if is_cveList is not None: 
            logging.info('CVE list detected') 
            return 'cve'
            #self.findAttackTechniques(self.security_findings_dictionary_list, self.implemented_controls_dictionary_list, is_cveList)
        elif is_cweList is not None: 
            logging.info('CWE list detected')
            return 'cwe'
            #self.findAttackTechniques(self.security_findings_dictionary_list, self.implemented_controls_dictionary_list, is_cweList)
        else:
            print('Invalid (not \'cve\'/\'cwe\') item detected from the input json file')


    def createFindingsList(self, security_findings_dictionary_list):
        logging.info("Enterred createFindingsList method.")
        findings_list = []
        logging.info("Declared findings_list local variable.")
        logging.info("Iterating through the security_findings_dictionary_list. For each dictionary in the list, we will append the value to the findings_list.")
        for dict in security_findings_dictionary_list:
            for value in dict.values():
                findings_list.append(value)
        logging.info(f"Finished iterating through the security_findings_dictionary_list. Findings list: {findings_list}")
        logging.info("Will return findings_list.")  
        return findings_list 
    
    def createListFromCursor(self, cursor):
        logging.info("Enterred createListFromCursor method.")
        logging.info("Will iterate through the cursor. For each dictionary in the cursor, we will append the dictionary to the list.")
        list = []
        for dict in cursor:
            list.append(dict)
        logging.info(f"Finished iterating through the cursor. List: {list}")
        logging.info("Will return list.")
        return list


    def determineAttackTechniquesNotMitigated(self):
        logging.info("Enterred determineAttackTechniquesNotMitigated method.")
        logging.info("Will iterate through the cursor_techniques_and_findings. For each techniqueFinding dictionary in the cursor, we will extract the values and store them in a list.")
        if debugging == True:
            #self.db_query_service.print_cursor(self.cursor_techniques_and_findings) 
            pass
        for singleTechniqueFindingDictionary in self.cursor_techniques_and_findings:
            logging.info(f"Element in cursor is Single technique finding dictionary: {singleTechniqueFindingDictionary}")
            controlsToMitigateTechniques = [] # stores control that map to the specific technique
            logging.info("Declared controlsToMitigateTechniques list.")
            techniquesAndFindingsList = list(singleTechniqueFindingDictionary.values())
            logging.info(f"Created list from the singleTechniqueFindingDictionary. Techniques and findings list: {techniquesAndFindingsList}")
            techniqueMappedToFinding = techniquesAndFindingsList[0]
            logging.info(f"Get the technique mapped to finding: {techniqueMappedToFinding}")
            
            '''A new technique that we haven't included in the final lists. We will go to the tech-control collection,
            iterate through the edges, and identify the control. We will add the control to a list.
            We will check all implemented controls against that list. If the control is new,
            we will ADD THE TECHNIQUE to the list.'''
            logging.info("Will check if the technique mapped to the finding is not in the attackTechniquesUsableAgainstSecurityFindings list.")
            if techniqueMappedToFinding not in self.attackTechniquesUsableAgainstSecurityFindings:
                logging.info("Technique mapped to finding is not in the attackTechniquesUsableAgainstSecurityFindings list.")
                logging.info("Will iterate through the techniqueControlCollection. For each techniqueControlEdge in the collection, we will check if the '_from' key is equal to the techniqueMappedToFinding.")
                logging.info("If it is, we will append the '_to' key to the controlsToMitigateTechniques list.")
                logging.info("This way we map the techniques that can be used against the findings to the controls that can mitigate the techniques.")
                for techniqueControlEdge in self.db_query_service.db_connection.techniqueControlCollection: # Tech-control edge collection
                    if techniqueControlEdge['_from'] == techniqueMappedToFinding:
                        controlsToMitigateTechniques.append(techniqueControlEdge['_to'])
                #Para cada control en control_dict_list, #check si es igual al control que acabamos de decir que es necesario.
                #Si ya  esta, no metemos la tecnica en la lista.
                logging.info("Will iterate through the implemented_controls_dictionary_list. For each control in the list, we will check if the control is in the controlsToMitigateTechniques list.")
                logging.info("If it is, we will break the loop. If it is not, we will append the techniqueMappedToFinding to the attackTechniquesUsableAgainstSecurityFindings list.")
                logging.info("We will also append the techniquesAndFindingsList to the attackTechniqueIDsAndListOfMatchedFindings list.")
                in_list = False
                for a_ctrl in self.implemented_controls_dictionary_list:
                    for  ctrl_value in a_ctrl.values():
                        alreadyImplementedControl = 'control/' + str(ctrl_value)
                        if alreadyImplementedControl in controlsToMitigateTechniques:
                            in_list = True
                            break
                if not in_list:
                    self.attackTechniquesUsableAgainstSecurityFindings.append(techniqueMappedToFinding)
                    self.attackTechniqueIDsAndListOfMatchedFindings.append(techniquesAndFindingsList)
        logging.info(f"Attack techniques usable against security findings: {self.attackTechniquesUsableAgainstSecurityFindings}")
        logging.info("")
        logging.info(f"Attack technique IDs and list of matched findings: {self.attackTechniqueIDsAndListOfMatchedFindings}")
        logging.info("")
        logging.info("Will return attackTechniquesUsableAgainstSecurityFindings and attackTechniqueIDsAndListOfMatchedFindings.")
        return self.attackTechniquesUsableAgainstSecurityFindings,self.attackTechniqueIDsAndListOfMatchedFindings

    def buildRecommendationsTableData(self, cursorTechniquesAndControls):
        logging.info("Enterred buildRecommendationsTableData method.")
        logging.info("Will iterate through the cursorTechniquesAndControls. For each techniqueControl dictionary in the cursor, we will extract the values and store them in a list.")
        logging.info("For each techniqueControl dictionary, we will get the tech_id")
        logging.info("We will also iterate through the attackTechniqueIDsAndListOfMatchedFindings. For each techniqueAndFindingsList in the list, we will check if the technique ID is equal to the tech_id in the techniqueControl dictionary.")
        
        
        for techniqueControlDict in cursorTechniquesAndControls:
            tech_id = techniqueControlDict['tech_id']
            for techniqueAndFindingsList in self.attackTechniqueIDsAndListOfMatchedFindings:
                logging.info(f"techniqueAndFindingsList in attackTechniqueIDsAndListOfMatchedFindings: {techniqueAndFindingsList}")
                logging.info("Will check if the tech_id is equal to the techniqueAndFindingsList[0].")
                if tech_id == techniqueAndFindingsList[0]:
                    finding = 'cwe'
                    if 'cve' in techniqueAndFindingsList[1][0].lower():
                            finding = 'cve'
                    logging.info(f"Will create table item with the following values: {finding}, {tech_id}, {techniqueControlDict['tech_name']}")
                    table_item = {finding: techniqueAndFindingsList[1],'Technique ID': tech_id, 'Technique Name': techniqueControlDict['tech_name']} 
                    logging.info(f"Will add the control to the table item: {techniqueControlDict['ctrl']}")
                    table_item = table_item | {'Control (Name)': techniqueControlDict['ctrl']}
                    logging.info(f"Table item: {table_item}")
                    logging.info("Will append the table item to the self.recommendationsTableData list.")
                    self.recommendationsTableData.append(table_item)


    def addNodesAndEdgesToTacticsAndTechniquesGraph(self, cursorTacticToTechnique):
        logging.info("Enterred addNodesAndEdgesToTacticsAndTechniquesGraph method.")
        logging.info("Will iterate through the cursorTacticToTechnique. For each edge in the cursor, we will extract the items and add them to the tacticsAndTechniquesGraph.")
        for edge in cursorTacticToTechnique:
            logging.info(f"Edge: {edge}")
            tactic, technique = edge.items() # Tactic: ('From', 'tactic/TA0006'), Technique: ('To', 'technique/T1040')
            logging.info(f"From edge.items() we get: Tactic: {tactic}, Technique: {technique}")
            logging.info("adding nodes and edges to tactics and techniques graph")
            logging.info(f"The nodes are: {tactic[1]}, {technique[1]}")
            self.tacticsAndTechniquesGraph.add_nodes_from([tactic[1], technique[1]])
            logging.info("Nodes added to tactics and techniques graph.")
            logging.info("adding edges to tactics and techniques graph")
            logging.info(f"Adding edge to tacticsAndTechniquesGraph: {tactic[1]} -> {technique[1]}")
            self.tacticsAndTechniquesGraph.add_edge(tactic[1], technique[1])
            logging.info("Edge added to tactics and techniques graph.")
            logging.info(f"Adding tactic to tacticsList: {tactic[1]}")
            self.tacticsList.append(tactic[1])
            #self.tacticsOnlyGraph.add_node(tactic[1])
            logging.info("Tactic added to tacticsList.")
        logging.info("")
        logging.info("Finished adding nodes in the tactics and techniques graph: ")
        logging.info(f"Nodes in the tactics and techniques graph: {self.tacticsAndTechniquesGraph.nodes}")

        logging.info("")
        logging.info("Edges in the tactics and techniques graph: ")
        logging.info(f"Edges in the tactics and techniques graph: {self.tacticsAndTechniquesGraph.edges}")

        logging.info("")
        logging.info("Tactics list: ")
        logging.info(f"Tactics list: {self.tacticsList}")


    def addEdgesToTacticsAndTechniquesGraph(self, tacticToTacticEdgeCollection):
        logging.info("Enterred addEdgesToTacticsAndTechniquesGraph method.")
        logging.info("Will iterate through the tacticToTacticEdgeCollection. For each edge in the collection, we will extract the items and add them to the tacticsAndTechniquesGraph.")
        for edge in tacticToTacticEdgeCollection:
            logging.info("adding edges to tactics and techniques graph")
            logging.info(f"Edge: {edge}")
            logging.info("Checking if edge['_from'] and edge['_to'] are in the tactics list.")
            logging.info(f"tacticsList: {self.tacticsList}")
            if edge['_from'] in self.tactic_original_id_list and edge['_to'] in self.tactic_original_id_list: # Never true?
                logging.info("")
                logging.info("Edge in tactics list true")
                logging.info("")
                # Add edges with debugging statements
                '''try:
                    logging.info(f"Adding edge to tacticsAndTechniquesGraph: {edge['_from']} -> {edge['_to']}")
                    self.tacticsAndTechniquesGraph.add_edge(edge['_from'], edge['_to'])
                    logging.info(f"Successfully added edge to tacticsAndTechniquesGraph: {edge['_from']} -> {edge['_to']}")
                except Exception as e:
                    logging.error(f"Error adding edge to tacticsAndTechniquesGraph: {e}")
                    logging.error(traceback.format_exc())'''

                try:
                    logging.info(f"Adding edge to tacticsOnlyGraph: {edge['_from']} -> {edge['_to']}")
                    self.tacticsOnlyGraph.add_edge(edge['_from'], edge['_to'])
                    logging.info(f"Successfully added edge to tacticsOnlyGraph: {edge['_from']} -> {edge['_to']}")
                except Exception as e:
                    logging.info(f"Error adding edge to tacticsOnlyGraph: {e}")

                '''logging.info(f"Adding edge to tacticsAndTechniquesGraph: {edge['_from']} -> {edge['_to']}")
                self.tacticsAndTechniquesGraph.add_edge(edge['_from'], edge['_to'])
                logging.info(f"Successfully added edge to tacticsAndTechniquesGraph: {edge['_from']} -> {edge['_to']}")
                
                logging.info(f"Adding edge to tacticsOnlyGraph: {edge['_from']} -> {edge['_to']}")
                self.tacticsOnlyGraph.add_edge(edge['_from'], edge['_to'])
                logging.info(f"Successfully added edge to tacticsOnlyGraph: {edge['_from']} -> {edge['_to']}")'''
                
                #self.tacticsAndTechniquesGraph.add_edge(edge['_from'], edge['_to'])
                #self.tacticsOnlyGraph.add_edge(edge['_from'], edge['_to'])
                # log the edges in the tactics only graph
        '''logging.info("")
        logging.info("Finished adding edges in the tactics only graph: ")
        logging.info(f"Edges in the tacticsAndTechniquesGraph: {self.tacticsAndTechniquesGraph.edges}")'''

        logging.info("PROBLEM!!!")
        logging.info(f"Nodes in the tactics only graph: {self.tacticsOnlyGraph.nodes}")
        logging.info(f"Edges in the tactics only graph: {self.tacticsOnlyGraph.edges}")
        '''Nodes in the tactics only graph:  ['tactic/tactic_00003', 'tactic/tactic_00005']
        Edges in the tactics only graph: [('tactic/tactic_00003', 'tactic/tactic_00005')]'''


    def sort_list(self, a_list):
        return sorted(a_list, key=lambda tup: tup[1], reverse=False)
    
    # finds priority of tactic
    def show_prioritize(self, user_priority_BRONtacticID):
        logging.info("Enterred show_prioritize method.")
        # priority of tactic
        high = []
        mid = []
        low = []

        # iterate over every node in the graph
        for node in self.tacticsAndTechniquesGraph.__iter__():
            logging.info(f"Node: {node}")
            # Nodes: ['tactic/TA0002', 'technique/T1040', ...]
            # Edges: [('tactic/TA0002', 'technique/T1040'), ...]
            '''Node: tactic/TA0006
            :Node: technique/T1040
            :Node: tactic/TA0007
            :Node: tactic/TA0009
            :Node: technique/T1056.004
            :Node: tactic/TA0040
            :Node: technique/T1499'''
            # if its a tactic node
            if 'tactic' in node:
                logging.info(f"Node is a tactic: {node}")
                
                # start the edge type counters
                cnt_tac = 0
                cnt_tech = 0

                # if the tactic is the one that user specified, prioritize the node
                if user_priority_BRONtacticID != None and user_priority_BRONtacticID in node:
                    high.append((node, 0))
                    f = open('/shared/debug_input.txt', 'a')
                    f.write('User selected tactic: ' + user_priority_BRONtacticID + '\n') # This works
                    f.close()
                else:
                    for neighbor in self.tacticsAndTechniquesGraph.neighbors(node):
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
                            low.append((node, cnt_tech))
                        case 1:
                            mid.append((node, cnt_tech))
                        case _:
                            high.append((node, cnt_tech))
     
        # sort the individual lists
        low = self.sort_list(low)
        mid = self.sort_list(mid)
        high = self.sort_list(high)


        # determine the highest priority node and change color to red
        # We want the tactic with the least amount of techniques to neutralize
        print('Low:', low, "\nMid:", mid, "\nHigh:", high)
        logging.info(f"Low: {low}, Mid: {mid}, High: {high}")
        if high.__len__() > 0 and self.tacticsAndTechniquesGraph.has_node(high[0][0]):
            self.tacticsAndTechniquesGraph.add_node(high[0][0], color='red')
        elif mid.__len__() > 0 and self.tacticsAndTechniquesGraph.has_node(mid[0][0]):
            self.tacticsAndTechniquesGraph.add_node(mid[0][0], color='red')
        elif low.__len__() > 0 and self.tacticsAndTechniquesGraph.has_node(low[0][0]):
            self.tacticsAndTechniquesGraph.add_node(low[0][0], color='red')
        else:
            pass

        # returns a list that has all prioritize lists
        return high + mid + low



@priority_blueprint.route('/table_data', methods=['GET','POST'])
def priority():
    # Current working directory or project root
    cur_dir = os.getcwd()
    
    # Initialize components
    db_connection = DatabaseConnection()
    query_service = DatabaseQueryService(db_connection)
    data_manager = ManageData(cur_dir, query_service)
    return data_manager.jsonTechniquesAndControls
    
    # Define the path to the HTML file
    '''html_file_path = '../shared/table.html'  # Use an absolute path or correct relative path

    try:
        # Verify that the file exists
        if not os.path.exists(html_file_path):
            logging.error(f'File not found: {html_file_path}')
            return f'Error: File not found - {html_file_path}', 404

        # Send the file using send_file, with cache-control headers
        response = make_response(send_file(html_file_path, mimetype='text/html'))

        # Add cache-control headers to prevent caching
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

        return response

    except Exception as e:
        logging.error(f'Error occurred: {str(e)}')
        return str(e), 500'''




def main():
    # Current working directory or project root
    '''cur_dir = os.getcwd()
    
    # Initialize components
    db_connection = DatabaseConnection()
    query_service = DatabaseQueryService(db_connection)
    data_manager = ManageData(cur_dir, query_service)'''
    '''logging.info("data_manager.cursor_techniques_and_findings:")
    data_manager.db_query_service.print_cursor(data_manager.cursor_techniques_and_findings)
    logging.info("data_manager.cursor_techniques_and_controls:")
    data_manager.db_query_service.print_cursor(data_manager.cursor_techniques_and_controls)'''
    '''control_prioritization = ControlPrioritization()
    visualizer = CreateVisualizations()'''

    # Load input data. Returns security_findings_dictionary_list, implemented_controls_dictionary_list
    #security_findings, implemented_controls, vulnerable_functions = data_manager.load_data()
    '''if debugging == True:
        logging.info(f"Findings dict: {security_findings}")
        logging.info(f"Implemented controls dict: {implemented_controls}")
        logging.info(f"vulnerable_functions: {vulnerable_functions}")'''
        #pass

    # Get techniques not mitigated
    '''unmitigated_techniques, matched_findings = control_prioritization.determine_unmitigated_techniques(
        security_findings, implemented_controls
    )
    if debugging == True:
        logger.info(f"Unmitigated techniques: {unmitigated_techniques}")
        logger.info(f"Matched findings: {matched_findings}")
        pass'''

    # Execute database queries using query service
    '''cursor_techniques_and_controls = query_service.fetch_priority_controls(unmitigated_techniques)
    recommendations_table = control_prioritization.build_recommendations_table_data(cursor_techniques_and_controls)
    
    cursor_tactic_to_technique = query_service.fetch_tactics_to_techniques(unmitigated_techniques)

    # Generate visualizations
    visualizer.create_visualizations(cursor_tactic_to_technique, recommendations_table)

    # Output or further processing
    logger.info("Generated Recommendations Table:")
    logger.info(recommendations_table)'''
    pass

if __name__ == "__main__":
    main()
