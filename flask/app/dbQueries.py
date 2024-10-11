# Right now this file is called from the test_dependencies.py file.
# Important: cursors can only be iterated on once. 
# If you want to iterate on the cursor multiple times, you need to store the results in a list.
from flask import Flask, jsonify
import os
import json
import logging
from arango.client import ArangoClient
import networkx as nx
from pyvis import network as net
import json2table
from typing import List, Dict, Tuple, Any
import ast

logging.basicConfig(level=logging.INFO)
debugging = True

class DatabaseConnection:
    def __init__(self):
        """Initialize the connection to the ArangoDB database."""
        arango_url = os.getenv('ARANGO_DB_URL')
        arango_db_name = os.getenv('ARANGO_DB_NAME')
        arango_username = os.getenv('ARANGO_DB_USERNAME')
        arango_password = os.getenv('ARANGO_DB_PASSWORD')

        try:
            self.client = ArangoClient(hosts=arango_url)
            self.db = self.client.db(arango_db_name, username=arango_username, password=arango_password)
            self.techniqueControlCollection = self.db.collection('TechniqueControl')
            self.tacticToTacticEdgeCollection = self.db.collection('TacticTactic')
        except Exception as e:
            logging.error(f"Failed to connect to ArangoDB: {e}")
            raise e

    def execute_aql(self, query: str, bind_vars: Dict[str, Any]) -> Any:
        """Executes an Arango Query Language (AQL) query on the ArangoDB database.
            bind_vars: Dict[str, Any]: A dictionary of variables that are "bound" to the query. 
            These are the parameters that you can use within your AQL query to avoid hardcoding values directly 
            in the query string.
            Return Type
            -> Any: This indicates that the method can return any type of value, 
            as it depends on the result of the executed query.
            ttl=300 argumement used below: Sets a Time-To-Live (TTL) of 300 seconds for the query. 
            The return is as specified in the query."""
        try:
            return self.db.aql.execute(query, bind_vars=bind_vars, ttl=300) 
        except Exception as e:
            logging.info(f"Failed to execute AQL query: {e}") # e is the exception message.
            raise 



class DatabaseQueryService:
    def __init__(self, db_connection: DatabaseConnection):
        """Handles execution of predefined database queries."""
        self.db_connection = db_connection

    def fetch_priority_controls(self, techniques: List[str]) -> Any:
        """Fetch controls for the given techniques."""
        priority_controls_query = '''
            FOR tech IN technique
                FILTER tech._id IN @attackTechniquesUsableAgainstSecurityFindings
                FOR tech_ctrl IN TechniqueControl
                    FILTER tech_ctrl._from == tech._id
                    FOR ctrl IN control
                        FILTER ctrl._id == tech_ctrl._to
                        COLLECT tech_id = tech._id, tech_name = tech.name INTO ctrl = ctrl.id_name
                        RETURN DISTINCT { tech_id: tech_id, tech_name: tech_name, ctrl: UNIQUE(ctrl) }
        '''
        bind_vars = {'attackTechniquesUsableAgainstSecurityFindings': techniques}
        return self.db_connection.execute_aql(priority_controls_query, bind_vars)

    def fetch_tactics_to_techniques(self, techniques: List[str]) -> Any:
        """Fetch tactic to technique relationships."""
        tactic_to_technique_query = '''
            FOR item IN @attackTechniquesUsableAgainstSecurityFindings
                FOR e, v, p IN 1..2 INBOUND item TacticTechnique
                RETURN { From: v._from, To: v._to }
        '''
        bind_vars = {'attackTechniquesUsableAgainstSecurityFindings': techniques}
        return self.db_connection.execute_aql(tactic_to_technique_query, bind_vars)

    def fetch_tactic_id(self, user_selected_tactic_id: str) -> Any:
        """Fetch BRON tactic ID for the given user-selected MITRE tactic ID."""
        tactic_id_query = '''
            FOR tac IN tactic
                FILTER tac.original_id == @userSelectedMITRETacticID
                RETURN tac._id
        '''
        bind_vars = {'userSelectedMITRETacticID': user_selected_tactic_id}
        return self.db_connection.execute_aql(tactic_id_query, bind_vars)
    
    
    def fetch_attacks_against_cwes(self, findings_list: List[str]) -> Any:
        logging.info("Enterred fetch_attacks_against_cwes method.")
        logging.info(f"findings_list: {findings_list}")
        """Fetch attacks against the given CWEs."""
        attacks_against_cwe_query = 'for cwe in cwe '\
            + 'filter cwe.original_id in @cwe_list '\
            + 'for capec_cwe in CapecCwe '\
            + 'filter capec_cwe._to == cwe._id '\
            + 'for tc in TechniqueCapec '\
            + 'filter tc._to == capec_cwe._from '\
            + 'collect tech=tc._from into cwe_id=cwe.original_id '\
            + 'return {tech:tech, cwe:unique(cwe_id)}'
        bind_vars = {'cwe_list': findings_list}
        return self.db_connection.execute_aql(attacks_against_cwe_query, bind_vars)
    
    def fetch_attacks_against_cves(self, findings_list: List[str]) -> Any:
        """Fetch attacks against the given CWEs."""
        attacks_against_cve_query = 'for cve in cve '\
            + 'filter cve.original_id in @cve_list '\
            + 'for cwe_cve in CweCve '\
            + 'filter cwe_cve._to == cve._id '\
            + 'for capec_cwe in CapecCwe '\
            + 'filter capec_cwe._to == cwe_cve._from '\
            + 'for tc in TechniqueCapec '\
            + 'filter tc._to == capec_cwe._from '\
            + 'collect tech=tc._from into cve_id=cve.original_id '\
            + 'return {tech:tech, cve:unique(cve_id)}'
        bind_vars = {'cve_list': findings_list}
        return self.db_connection.execute_aql(attacks_against_cve_query, bind_vars)


    # Just for debugging purposes. The cursor can only be iterated on once.
    def print_cursor(self, cursor: Any):
        """Print the results of a cursor."""
        logging.info("Enterred print_cursor method.")
        for doc in cursor:
            logging.info(doc)

    def get_techniques(self, cursor: Any):
        techniques = [doc for doc in cursor]  # Convert cursor to list of dictionaries
        return jsonify(techniques)

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
        
        self.findings_list = self.createFindingsList(self.security_findings_dictionary_list)
        if debugging == True:
            logging.info(f"findings_list: {self.findings_list}")
        self.cursor_techniques_and_findings = None
        self.finding_type = self.weaknessOrVulnerability()
        if self.finding_type == 'cve':
            self.cursor_techniques_and_findings = self.db_query_service.fetch_attacks_against_cves(self.findings_list)
        else:
            self.cursor_techniques_and_findings = self.db_query_service.fetch_attacks_against_cwes(self.findings_list)
            if debugging == True:
                #self.db_query_service.print_cursor(self.cursor_techniques_and_findings)
                pass
        self.attackTechniquesUsableAgainstSecurityFindings = [] 
        self.attackTechniqueIDsAndListOfMatchedFindings = []
        self.determineAttackTechniquesNotMitigated()
        self.cursor_techniques_and_controls = self.db_query_service.fetch_priority_controls(self.attackTechniquesUsableAgainstSecurityFindings)
        # logging.info("Printing cursor_techniques_and_controls:")
        # Prints dictionaries where each dictionary has tech_id, tech_name, and ctrl list
        # self.db_query_service.print_cursor(self.cursor_techniques_and_controls)  
        # logging.info("Returned from print_cursor method.")
        self.jsonTechniquesAndControls = self.bd_query_service.get_techniques(self.cursor_techniques_and_controls) 

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


def main():
    # Current working directory or project root
    cur_dir = os.getcwd()
    
    # Initialize components
    db_connection = DatabaseConnection()
    query_service = DatabaseQueryService(db_connection)
    data_manager = ManageData(cur_dir, query_service)
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

if __name__ == "__main__":
    main()
