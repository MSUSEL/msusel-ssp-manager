import json
import os.path
from arango.client import ArangoClient
import networkx as nx
from pyvis import network as net
import os
import json2table
import logging


logging.basicConfig(level=logging.INFO)

'''logging.basicConfig(
    filename='/shared/app.log',          # Name of the log file
    filemode='a',                # 'a' for append, 'w' for overwrite
    level=logging.DEBUG,         # Set the logging level (DEBUG, INFO, WARNING, etc.)
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'  # Define log format
)'''

class DatabaseConnection:
    def __init__(self):
        arango_url = os.getenv('ARANGO_DB_URL')
        logging.info("got arrango_url from environment variable.")
        arango_db_name = os.getenv('ARANGO_DB_NAME')
        logging.info("got arrango_db_name from environment variable.")
        arango_username = os.getenv('ARANGO_DB_USERNAME')
        logging.info("got arrango_username from environment variable.")
        arango_password = os.getenv('ARANGO_DB_PASSWORD')
        logging.info("got arrango_password from environment variable.")
        '''arango_url = os.getenv('ARANGO_DB_URL', 'http://brondb:8529')
        arango_db_name = os.getenv('ARANGO_DB_NAME', 'BRON')
        arango_username = os.getenv('ARANGO_DB_USERNAME', 'root')
        arango_password = os.getenv('ARANGO_DB_PASSWORD', 'changeme')'''

        self.client = ArangoClient(hosts=arango_url)
        logging.info("Initialized ArangoClient")
        self.db = self.client.db(arango_db_name, username=arango_username, password=arango_password)
        logging.info("Got DB from client.")
        self.techniqueControlCollection = self.db.collection('TechniqueControl')
        logging.info("Initialized techniqueControl edge collection attribute.")
        self.tacticToTacticEdgeCollection = self.db.collection('TacticTactic')
        logging.info("Initialized tacticTactic edge collection attribute.")

    
class ControlPrioritization:
    def __init__(self, DatabaseConnection): 
        self.attackTechniquesUsableAgainstSecurityFindings = [] # DB holds Attack Technique ids as 'technique/technique_00030', for example.
        logging.info("Declared attackTechniquesUsableAgainstSecurityFindings attribute, a list that will hold attach techniques in the format 'technique/technique_00030'.")
        self.attackTechniqueIDsAndListOfMatchedFindings = []
        logging.info("Declared attackTechniqueIDsAndListOfMatchedFindings list.")
        self.DBConnection = DatabaseConnection
        logging.info("Initialized DBConnection object")
        # query to get the data for html table  
        self.priorityControlsQuery = 'for tech in technique '\
                + 'filter tech._id in @attackTechniquesUsableAgainstSecurityFindings '\
                + 'for tech_ctrl in TechniqueControl '\
                + 'filter tech_ctrl._from == tech._id '\
                + 'for ctrl in control '\
                + 'filter ctrl._id == tech_ctrl._to '\
                + 'collect tech_id=tech._id, tech_name=tech.name into ctrl=ctrl.id_name '\
                + 'return distinct {tech_id: tech_id, tech_name: tech_name, ctrl: unique(ctrl)}'
        logging.info("Initialized priorityControlsQuery")
        self.recommendationsTableData = []
        logging.info("Declared recommendationsTableData list")
        self.tacticToTechniqueQuery = 'for item in @attackTechniquesUsableAgainstSecurityFindings ' \
            + 'for e, v, p in 1..2 inbound ' \
            + 'item TacticTechnique ' \
            + 'return { From: v._from, To: v._to }'
        logging.info("Initialized tacticToTechniqueQuery")
        self.getTacticIDForUserSelectionQuery = 'for tac in tactic '\
            + 'filter tac.original_id == @userSelectedMITRETacticID '\
            + 'return tac._id'
        logging.info("Initialized getTacticIDForUserSelectionQuery")
   
    def determineAttackTechniquesNotMitigated(self, cursorTechniquesAndFindings, implemented_controls_dictionary_list):
        logging.info("Enterred determineAttackTechniquesNotMitigated method.")
        logging.info("Will iterate through the cursorTechniquesAndFindings. For each techniqueFinding dictionary in the cursor, we will extract the values and store them in a list.")
        for singleTechniqueFindingDictionary in cursorTechniquesAndFindings:
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
                for techniqueControlEdge in self.DBConnection.techniqueControlCollection: # Tech-control edge collection
                    if techniqueControlEdge['_from'] == techniqueMappedToFinding:
                        controlsToMitigateTechniques.append(techniqueControlEdge['_to'])
                #Para cada control en control_dict_list, #check si es igual al control que acabamos de decir que es necesario.
                #Si ya  esta, no metemos la tecnica en la lista.
                logging.info("Will iterate through the implemented_controls_dictionary_list. For each control in the list, we will check if the control is in the controlsToMitigateTechniques list.")
                logging.info("If it is, we will break the loop. If it is not, we will append the techniqueMappedToFinding to the attackTechniquesUsableAgainstSecurityFindings list.")
                logging.info("We will also append the techniquesAndFindingsList to the attackTechniqueIDsAndListOfMatchedFindings list.")
                in_list = False
                for a_ctrl in implemented_controls_dictionary_list:
                    for  ctrl_value in a_ctrl.values():
                        alreadyImplementedControl = 'control/' + str(ctrl_value)
                        if alreadyImplementedControl in controlsToMitigateTechniques:
                            in_list = True
                            break
                if not in_list:
                    self.attackTechniquesUsableAgainstSecurityFindings.append(techniqueMappedToFinding)
                    self.attackTechniqueIDsAndListOfMatchedFindings.append(techniquesAndFindingsList)
        #logging.info("log 7 OK")
        #logging.info("log 8 OK")
        '''logging.info("")
        logging.info(f"Attack techniques usable against security findings: {self.attackTechniquesUsableAgainstSecurityFindings}")
        logging.info("")
        logging.info(f"Attack technique IDs and list of matched findings: {self.attackTechniqueIDsAndListOfMatchedFindings}")
        logging.info("")'''
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
        

class Match_VulnerabilitesAndWeakness_ToAttackTactics_AndTechniques:
    def __init__(self, curDir, DatabaseConnection, ControlPrioritization, CreateVisualizations):
        self.security_findings_file_path = os.path.join(curDir, "/shared", 'vulnerabilities.json')
        logging.info("Initialized security_findings_file_path attribute.")
        self.controls_file_path = os.path.join(curDir, "/shared", 'controls.json')
        logging.info("Initialized controls_file_path attribute.")
        self.implemented_controls_dictionary_list = []
        logging.info("Declared implemented_controls_dictionary_list attribute.")
        self.security_findings_dictionary_list = []
        logging.info("Declared security_findings_dictionary_list attribute.")
        # Query to get the techniques that are related to the CVEs in the findings_list.
        self.attacksAgainstCVEsQuery = 'for cve in cve '\
            + 'filter cve.original_id in @cve_list '\
            + 'for cwe_cve in CweCve '\
            + 'filter cwe_cve._to == cve._id '\
            + 'for capec_cwe in CapecCwe '\
            + 'filter capec_cwe._to == cwe_cve._from '\
            + 'for tc in TechniqueCapec '\
            + 'filter tc._to == capec_cwe._from '\
            + 'collect tech=tc._from into cve_id=cve.original_id '\
            + 'return {tech:tech, cve:unique(cve_id)}'
        logging.info("Initialized attacksAgainstCVEsQuery attribute.")
        # Query to get the techniques that are related to the CWEs in the findings_list.
        self.attacksAgainstCWEsQuery = 'for cwe in cwe '\
            + 'filter cwe.original_id in @cwe_list '\
            + 'for capec_cwe in CapecCwe '\
            + 'filter capec_cwe._to == cwe._id '\
            + 'for tc in TechniqueCapec '\
            + 'filter tc._to == capec_cwe._from '\
            + 'collect tech=tc._from into cwe_id=cwe.original_id '\
            + 'return {tech:tech, cwe:unique(cwe_id)}'
        logging.info("Initialized attacksAgainstCWEsQuery attribute.")
        self.findings_list = []
        logging.info("Declared findings_list attribute.")
        self.cursor = None
        logging.info("Declared cursor attribute.")
        self.DBConnection = DatabaseConnection
        logging.info("Initialized DBConnection object.")
        self.ControlPrioritization = ControlPrioritization
        logging.info("Initialized ControlPrioritization object.")
        self.CreateVisualizations = CreateVisualizations
        logging.info("Initialized CreateVisualizations object.")

    def makeMatch(self):
        logging.info("Calling createDictionaryListsFromInputFiles method.")
        self.createDictionaryListsFromInputFiles()
        logging.info("Returned from createDictionaryListsFromInputFiles method.")
        logging.info("Calling weaknessOrVulnerability method.")
        self.weaknessOrVulnerability()
        
    def createDictionaryListsFromInputFiles(self):
        logging.info("Enterred createDictionaryListsFromInputFiles method.")
        security_findingsFile = open(self.security_findings_file_path, 'r') 
        self.security_findings_dictionary_list = json.load(security_findingsFile)
        security_findingsFile.close()
        logging.info("Opened security_findingsFile")
        logging.info("Closed security_findingsFile") 
        logging.info("Created security_findings_dictionary_list from the security_findings_file using json.load.")
        logging.info(f"Logging security findings dictionary list. Observe the format of the contents: {self.security_findings_dictionary_list}")
        logging.info("")
        logging.info("")
        controls_file = open(self.controls_file_path, 'r')
        self.implemented_controls_dictionary_list = json.load(controls_file) # Ex: [{'control': 'CM-7'}, {'control': 'SC-7'}]
        controls_file.close()
        logging.info("Opened controls_file")
        logging.info("Closed controls_file")
        logging.info("Created implemented_controls_dictionary_list from the controls_file using json.load.")
        logging.info(f"Logging implemented controls dictionary list. Observe the format of the contents: {self.implemented_controls_dictionary_list}")
        logging.info("")
        logging.info("")

    def weaknessOrVulnerability(self):
        logging.info("Enterred weaknessOrVulnerability method. This method determines whether the input json file contains a list of weaknesses (cwe) or vulnerabilities (cve).")
        is_cveList = self.security_findings_dictionary_list[0].get('cve', None)
        logging.info(f"Get the value of the 'cve' key from the first item in the security_findings_dictionary_list: {is_cveList}. If it is not None, the input json file contains a list of weaknesses.")
        is_cweList = self.security_findings_dictionary_list[0].get('cwe', None)
        logging.info(f"Get the value of the 'cwe' key from the first item in the security_findings_dictionary_list: {is_cweList}. If it is not None, the input json file contains a list of vulnerabilities.")
        if is_cveList is not None: 
            logging.info('CVE list detected') 
            self.findAttackTechniques(self.security_findings_dictionary_list, self.implemented_controls_dictionary_list, is_cveList)
        elif is_cweList is not None: 
            logging.info('CWE list detected')
            logging.info(f"Calling findAttackTechniques method. The arguments are: {self.security_findings_dictionary_list}, {self.implemented_controls_dictionary_list}, {is_cweList}")
            self.findAttackTechniques(self.security_findings_dictionary_list, self.implemented_controls_dictionary_list, is_cweList)
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
    
    def mapFindingstoMITREAttackTechniques(self, findings_list, finding_type):
        logging.info("Enterred mapFindingstoMITREAttackTechniques method. This method will execute the self.attacksAgainstCWEsQuery to map the findings in the findings_list to MITRE ATT&CK techniques.")
        if 'CVE' in finding_type:
            query = self.attacksAgainstCVEsQuery
            # Specify that @cve_list in the query is cve_list.
            bind = {'cve_list': findings_list}
        else: # CWE case
            query = self.attacksAgainstCWEsQuery
            logging.info(f"Query: {query}")
            # Specify that @cwe_list in the query is cwe_list.
            bind = {'cwe_list': findings_list}
            logging.info(f"Bind variables: {bind}")
        # Execute the query.
        logging.info("Will execute the query. The method will return a cursor object.")
        return self.DBConnection.db.aql.execute(query, bind_vars=bind, ttl=300)

    def findAttackTechniques(self, security_findings_dictionary_list, implemented_controls_dictionary_list, finding_type):
        logging.info("Enterred findAttackTechniques method.")   
        logging.info("Will call createFindingsList method passing security_findings_dictionary_list as an argument. This method will make a list from the values in the dictionary.")
        self.findings_list = self.createFindingsList(security_findings_dictionary_list)
        logging.info("Returned from createFindingsList method. Back in findAttackTechniques method.")
        logging.info(f"Findings list was returned and stored in the self.findings_list attibute: {self.findings_list}")

        logging.info("Will call mapFindingstoMITREAttackTechniques method passing the findings_list and finding_type as arguments.")
        # Cursor not being used after this point??? Yes, name is changed in the function parameter to cursorTechniquesAndFindings
        self.cursor = self.mapFindingstoMITREAttackTechniques(self.findings_list, finding_type)
        logging.info("Returned from mapFindingstoMITREAttackTechniques method. Back in findAttackTechniques method. The return value is stored in the self.cursor attribute.")
        logging.info(f"Cursor object: {self.cursor}")
        logging.info("Will call controlPrioritizationWrapperFunction method passing implemented_controls_dictionary_list, cursorTechniquesAndFindings, and ControlPrioritization as arguments.")
        self.controlPrioritizationWrapperFunction(implemented_controls_dictionary_list, self.cursor, self.ControlPrioritization)

    def controlPrioritizationWrapperFunction(self, implemented_controls_dictionary_list, cursorTechniquesAndFindings, ControlPrioritization):
        logging.info("Enterred controlPrioritizationWrapperFunction method.")
        logging.info("Will call ControlPrioritization.determineAttackTechniquesNotMitigated method passing cursorTechniquesAndFindings which contains dictionaries with attack techniques and cwe IDs and implemented_controls_dictionary_list as arguments. This method will determine the attack techniques that are not mitigated by the implemented controls.")
        ControlPrioritization.determineAttackTechniquesNotMitigated(cursorTechniquesAndFindings, implemented_controls_dictionary_list)
        logging.info("Returned from ControlPrioritization.determineAttackTechniquesNotMitigated method. Back in controlPrioritizationWrapperFunction method.")
        
        logging.info("Get the priority controls query from the ControlPrioritization object.")
        query = ControlPrioritization.priorityControlsQuery
        logging.info(f"Query: {query}")
        logging.info("Binding the attackTechniquesUsableAgainstSecurityFindings attribute to the query.")
        bind_var = {'attackTechniquesUsableAgainstSecurityFindings': ControlPrioritization.attackTechniquesUsableAgainstSecurityFindings}
        logging.info(f"Bind variables: {bind_var}")
        logging.info("Will execute the query. The method will return a cursor object.")
        cursorTechniquesAndControls = self.DBConnection.db.aql.execute(query, bind_vars=bind_var, ttl=300)
        logging.info("Returned from the query execution. Back in controlPrioritizationWrapperFunction method.")
        logging.info(f"Cursor techniques and controls: {cursorTechniquesAndControls}")
        #logging.info("")
        logging.info("Will call ControlPrioritization.buildRecommendationsTableData method passing cursorTechniquesAndControls as an argument.")
        ControlPrioritization.buildRecommendationsTableData(cursorTechniquesAndControls)
        logging.info("Returned from ControlPrioritization.buildRecommendationsTableData method. Back in controlPrioritizationWrapperFunction method.")
        logging.info(f"Recommendations table data: {ControlPrioritization.recommendationsTableData}")
        
        logging.info("Will get the ControlPrioritization object's tacticToTechniqueQuery attribute.")
        query = ControlPrioritization.tacticToTechniqueQuery
        logging.info(f"Query: {query}")
        logging.info("Binding the attackTechniquesUsableAgainstSecurityFindings attribute to the query.")
        bind_vars = {'attackTechniquesUsableAgainstSecurityFindings': ControlPrioritization.attackTechniquesUsableAgainstSecurityFindings}
        logging.info(f"Bind variables: {bind_vars}")
        logging.info("Will execute the query. The method will return a cursor object and store it in the cursorTacticToTechnique local variable.")
        cursorTacticToTechnique = self.DBConnection.db.aql.execute(query, bind_vars=bind_vars)
        logging.info("Returned from the query execution. Back in controlPrioritizationWrapperFunction method.")

        '''with open('/shared/input.txt', 'r') as in_txt:
            userSelectedMITRETacticID = in_txt.read()
              
        query = ControlPrioritization.getTacticIDForUserSelectionQuery
        bind_vars = {'userSelectedMITRETacticID': userSelectedMITRETacticID}
        cursorUserTacticID = self.DBConnection.db.aql.execute(query, bind_vars=bind_vars)'''

        # Store BRON tactic id
        userSelectedBRONTactic_id = ''
        logging.info("Initialized userSelectedBRONTactic_id local variable.")
        '''for tactic_id in cursorUserTacticID:
            userSelectedBRONTactic_id = tactic_id'''
        
        logging.info("Will call CreateVisualizations.make_graph method passing cursorTacticToTechnique, ControlPrioritization.recommendationsTableData, and userSelectedBRONTactic_id as arguments.")
        self.CreateVisualizations.make_graph(self.DBConnection.db, cursorTacticToTechnique, ControlPrioritization.recommendationsTableData, userSelectedBRONTactic_id)



class CreateVisualizations:
    def __init__(self):
        self.tacticsList = []
        logging.info("Declared tacticsList attribute")
        self.tacticsAndTechniquesGraph = nx.Graph()
        logging.info("Initialized tacticsAndTechniquesGraph. This is a networkx graph.")
        self.tacticsOnlyGraph = nx.DiGraph()
        logging.info("Initialized tacticsOnlyGraph attribute. This is a networkx digraph.")
        self.pyvisTacticsAndTechniquesGraph = net.Network(height='100vh', width='100%', notebook=True, bgcolor="#FFFFFF", font_color="black")
        logging.info("Initialized pyvisTacticsAndTechniquesGraph attribute. This is a pyvis network object.")
        self.pyvisAttackPathsGraph = net.Network(height='100vh', width='100%', notebook=True, bgcolor="#FFFFFF", font_color="black")
        logging.info("Initialized pyvisAttackPathsGraph attribute. This is a pyvis network object.")
        self.user_priority_BRONtacticID = None
        logging.info("Initialized user_priority_BROBtacticID attribute.")
        
    def addNodesAndEdgesToTacticsAndTechniquesGraph(self, cursorTacticToTechnique):
        logging.info("Enterred addNodesAndEdgesToTacticsAndTechniquesGraph method.")
        logging.info("Will iterate through the cursorTacticToTechnique. For each edge in the cursor, we will extract the items and add them to the tacticsAndTechniquesGraph.")
        for edge in cursorTacticToTechnique:
            logging.info(f"Edge: {edge}")
            tactic, technique = edge.items()
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
            if edge['_from'] in self.tacticsList and edge['_to'] in self.tacticsList: # Never true?
                logging.info("")
                logging.info("Edge in tactics list true")
                logging.info("")
                # Add edges with debugging statements
                '''try:
                    logging.info(f"Adding edge to tacticsAndTechniquesGraph: {edge['_from']} -> {edge['_to']}")
                    self.tacticsAndTechniquesGraph.add_edge(edge['_from'], edge['_to'])
                    logging.info(f"Successfully added edge to tacticsAndTechniquesGraph: {edge['_from']} -> {edge['_to']}")
                except Exception as e:
                    logging.info(f"Error adding edge to tacticsAndTechniquesGraph: {e}")

                try:
                    logging.info(f"Adding edge to tacticsOnlyGraph: {edge['_from']} -> {edge['_to']}")
                    self.tacticsOnlyGraph.add_edge(edge['_from'], edge['_to'])
                    logging.info(f"Successfully added edge to tacticsOnlyGraph: {edge['_from']} -> {edge['_to']}")
                except Exception as e:
                    logging.info(f"Error adding edge to tacticsOnlyGraph: {e}")'''

                logging.info(f"Adding edge to tacticsAndTechniquesGraph: {edge['_from']} -> {edge['_to']}")
                self.tacticsAndTechniquesGraph.add_edge(edge['_from'], edge['_to'])
                logging.info(f"Successfully added edge to tacticsAndTechniquesGraph: {edge['_from']} -> {edge['_to']}")
                
                logging.info(f"Adding edge to tacticsOnlyGraph: {edge['_from']} -> {edge['_to']}")
                self.tacticsOnlyGraph.add_edge(edge['_from'], edge['_to'])
                logging.info(f"Successfully added edge to tacticsOnlyGraph: {edge['_from']} -> {edge['_to']}")
                
                #self.tacticsAndTechniquesGraph.add_edge(edge['_from'], edge['_to'])
                #self.tacticsOnlyGraph.add_edge(edge['_from'], edge['_to'])
                # log the edges in the tactics only graph
        logging.info("")
        logging.info("Finished adding edges in the tactics only graph: ")
        logging.info(f"Edges in the tacticsAndTechniquesGraph: {self.tacticsAndTechniquesGraph.edges}")

        logging.info("PROBLEM!!!")
        logging.info(f"Nodes in the tactics only graph: {self.tacticsOnlyGraph.nodes}")
        logging.info(f"Edges in the tactics only graph: {self.tacticsOnlyGraph.edges}")

    def checkIfUserPriorityWasDetected(self, userSelectedBRONTactic_id):
        if userSelectedBRONTactic_id in self.tacticsList:
            self.user_priority_BRONtacticID = userSelectedBRONTactic_id
            f = open('/shared/debug_input.txt', 'a')
            f.write('User selected tactic: ' + self.user_priority_BRONtacticID + '\n')
            f.close()

    def createPyvisTacticsAndTechniquesGraph(self):
        logging.info("Enterred createPyvisTacticsAndTechniquesGraph method.")
        # translates networkx graph into PyViz graph
        logging.info("Will call self.pyvisTacticsAndTechniquesGraph.from_nx method passing the tacticsAndTechniquesGraph as an argument.")
        logging.info("This method will convert the networkx graph to a pyvis graph.")
        self.pyvisTacticsAndTechniquesGraph.from_nx(self.tacticsAndTechniquesGraph)
        logging.info("Returned from from_nx method. Back in createPyvisTacticsAndTechniquesGraph method.")
        logging.info("Will call self.pyvisTacticsAndTechniquesGraph.force_atlas_2based method.")
        logging.info("This method will apply the force atlas 2 based layout to the graph.")
        self.pyvisTacticsAndTechniquesGraph.force_atlas_2based()
        logging.info("Returned from force_atlas_2based method. Back in createPyvisTacticsAndTechniquesGraph method.")
        logging.info("Will call self.pyvisTacticsAndTechniquesGraph.show method passing './app/templates/graph.html' as an argument.")
        logging.info("This method will save the graph to the ./app/templates/graph.html file.")
        self.pyvisTacticsAndTechniquesGraph.show('./app/templates/graph.html')
        logging.info("Returned from show method. Back in createPyvisTacticsAndTechniquesGraph method.")
        logging.info("")
        logging.info("Contents of the graph html file: ")
        file_path = './app/templates/graph.html'
        try:
            # Open and read the file
            with open(file_path, 'r') as file:
                file_contents = file.read()
            
            # Log the contents of the file
            logging.info(f"Contents of {file_path}: {file_contents}")
        except Exception as e:
            logging.error(f"Error reading {file_path}: {e}")

    def createPyvisAttackPathsGraph(self, attackPathsGraph):
        logging.info("Enterred createPyvisAttackPathsGraph method.")
        # translates networkx graph into PyViz graph
        logging.info("Will call self.pyvisAttackPathsGraph.from_nx method passing the attackPathsGraph as an argument.")
        logging.info("This method will convert the networkx graph to a pyvis graph.")
        self.pyvisAttackPathsGraph.from_nx(attackPathsGraph)
        logging.info("Returned from from_nx method. Back in createPyvisAttackPathsGraph method.")
        logging.info("Will call self.pyvisAttackPathsGraph.force_atlas_2based method.")
        logging.info("This method will apply the force atlas 2 based layout to the graph.")
        self.pyvisAttackPathsGraph.force_atlas_2based()
        logging.info("Returned from force_atlas_2based method. Back in createPyvisAttackPathsGraph method.")
        logging.info("Will call self.pyvisAttackPathsGraph.show method passing './app/templates/network_flow.html' as an argument.")
        logging.info("This method will save the graph to the ./app/templates/network_flow.html file.")
        self.pyvisAttackPathsGraph.show('./app/templates/network_flow.html')
        # log contents of the ./app/templates/network_flow.html file
        # Path to the file
        logging.info("")
        logging.info("Contents of the network flow html file: ")
        file_path = './app/templates/network_flow.html'
        try:
            # Open and read the file
            with open(file_path, 'r') as file:
                file_contents = file.read()
            
            # Log the contents of the file
            logging.info(f"Contents of {file_path}: {file_contents}")
        except Exception as e:
            logging.error(f"Error reading {file_path}: {e}")


    def make_graph(self, db, cursorTacticToTechnique, recommendationsTableData, userSelectedBRONTactic_id):
        logging.info("Enterred make_graph method.")
        tacticToTacticEdgeCollection = db.collection('TacticTactic')
        logging.info("Initialized tacticToTacticEdgeCollection local variable.")

        logging.info("Will call addNodesAndEdgesToTacticsAndTechniquesGraph method passing cursorTacticToTechnique as an argument.")
        self.addNodesAndEdgesToTacticsAndTechniquesGraph(cursorTacticToTechnique)
        logging.info("Returned from addNodesAndEdgesToTacticsAndTechniquesGraph method. Back in make_graph method.")
        logging.info("Will call addEdgesToTacticsAndTechniquesGraph method passing tacticToTacticEdgeCollection as an argument.")
        self.addEdgesToTacticsAndTechniquesGraph(tacticToTacticEdgeCollection)
        logging.info("Returned from addEdgesToTacticsAndTechniquesGraph method. Back in make_graph method.")
        logging.info("Will call checkIfUserPriorityWasDetected method passing userSelectedBRONTactic_id as an argument. The user has an option to select a tactic, but it is not required.") 
        self.checkIfUserPriorityWasDetected(userSelectedBRONTactic_id)
        logging.info("Returned from checkIfUserPriorityWasDetected method. Back in make_graph method.")

        logging.info("Will call show_prioritize method passing userSelectedBRONTactic_id as an argument.")
        prioritize_lists = self.show_prioritize(self.user_priority_BRONtacticID) # runs algorithm that finds the prioritized paths
        logging.info("Returned from show_prioritize method. Back in make_graph method.")
        logging.info(f"Prioritize lists is optional: {prioritize_lists}")
        
        logging.info("Will call create_table method passing db, prioritize_lists, and recommendationsTableData as arguments.")
        self.create_table(db, prioritize_lists, recommendationsTableData)
        logging.info("Returned from create_table method. Back in make_graph method.")
        
        # Check if vulnerability effectiveness analysis has been run
        logging.info("Will check if the vulnerability effectiveness analysis has been run by checking if the ./app/artifacts/calledVulnerableFunctionsObjectList.txt file exists.")
        if os.path.exists('./app/artifacts/calledVulnerableFunctionsObjectList.txt'):
            logging.info("Vulnerability effectiveness analysis has been run.")
            logging.info("Will call create_vulntable method.")
            self.create_vulntable() # If so, show functions in the dependencies that are called.
            logging.info("Returned from create_vulntable method. Back in make_graph method.")
        
        
        logging.info("Will call makeAttackPathsGraph method passing the tacticsAndTechniquesGraph and tacticsOnlyGraph as arguments.")
        attackPathsGraph = self.makeAttackPathsGraph(self.tacticsAndTechniquesGraph, self.tacticsOnlyGraph)
        logging.info("Returned from makeAttackPathsGraph method. Back in make_graph method.")
        logging.info("Will call createPyvisTacticsAndTechniquesGraph method.")
        self.createPyvisTacticsAndTechniquesGraph()
        logging.info("Returned from createPyvisTacticsAndTechniquesGraph method. Back in make_graph method.")
        logging.info("Will call createPyvisAttackPathsGraph method passing attackPathsGraph as an argument.")
        self.createPyvisAttackPathsGraph(attackPathsGraph)
        logging.info("")


    # method to sort the individual priority lists
    def sort_list(self, a_list):
        return sorted(a_list, key=lambda tup: tup[1], reverse=False)  # lambda arguments : expression


    # finds priority of tactic
    def show_prioritize(self, user_priority_BRONtacticID):
        logging.info("Enterred show_prioritize method.")
        # priority of tactic
        high = []
        mid = []
        low = []

        # iterate over every node in the graph
        for node in self.tacticsAndTechniquesGraph.__iter__():
            # if its a tactic node
            if 'tactic' in node:
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
        
        # Save high list to file
        with open('/shared/high.txt', 'a') as out_file:
            for item in high: # item is a tuple, tactic ID, and some munber.
                out_file.write(str(item) + "\n")
            out_file.write("\n")
            out_file.close()
        
        
        
        
        # sort the individual lists
        low = self.sort_list(low)
        mid = self.sort_list(mid)
        high = self.sort_list(high)


        with open('/shared/high.txt', 'a') as out_file:
            for item in high:
                out_file.write(str(item) + "\n")
            out_file.write("\n")
            out_file.close()

        # determine the highest priority node and change color to red
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


    # creates a html table that contains data related to the generated graphs
    def create_table(self, db, prioritize_lists, recommendationsTableData):
        logging.info("Enterred create_table method.")
        table_list = [] # will contain data for each table
        logging.info("Declared table_list local variable.")

        logging.info("Will write the prioritize_lists to the prioritize_Lists.txt file.")
        with open('/shared/prioritize_Lists.txt', 'a') as out_file:
            for item in prioritize_lists: # item is a tuple, tactic ID, and some munber.
                out_file.write(str(item) + "\n")
            out_file.write("\n")
            out_file.close() # They are in the correct order
        logging.info("prioritize_Lists.txt file written to ./shared.")


        # loop to find the technique that maps to the specific tactic
        logging.info("Will iterate through the prioritize_lists. For each item in the list, we will find the technique(s) that map from the specific tactic.")
        for obj in prioritize_lists:
            logging.info(f"Item in prioritize_lists: {obj}")
            tactic_id = obj[0] # obj -> ('tactic/tactic_00008', 0), for ex
            logging.info(f"Tactic ID extracted from obj: {tactic_id}")

            # finds technique(s) that map from the specific tactic
            query = 'for tac_tech in TacticTechnique '\
                + 'filter tac_tech._from == @tac_id '\
                + 'return distinct tac_tech._to'
            logging.info(f"Query: {query}")
            
            bind_var = {'tac_id': tactic_id}
            logging.info(f"Bind variables: {bind_var}")
            logging.info("Will execute the query. The method will return a cursor object.")
            cursor = db.aql.execute(query, bind_vars=bind_var)

            # checks whether the technique is in the graph
            logging.info("Will iterate through the cursor. For each technique in the cursor, we will check if it is in the tacticsAndTechniquesGraph.")
            for tech_id in cursor:
                logging.info(f"Technique ID: {tech_id}")
                logging.info("Will iterate through the recommendationsTableData. For each item in the list, we will check if the technique ID is in the item.")
                for data in recommendationsTableData:
                    logging.info(f"Item in recommendationsTableData: {data}")
                    if tech_id == data['Technique ID']:
                        logging.info("Technique ID found in the recommendationsTableData.")
                        logging.info("Will execute a query to get the tactic name.")
                        query = 'for tac in tactic '\
                        + 'filter tac._id == @tactic_id '\
                        + 'return tac.name'
                        logging.info(f"Query: {query}")
                        bind_var = {'tactic_id': tactic_id}
                        logging.info(f"Bind variables: {bind_var}")
                        logging.info("Will execute the query. The method will return a cursor object.")
                        cursor_tac = db.aql.execute(query, bind_vars=bind_var)
                        logging.info("Returned from the query execution. Back in create_table method.")
                        logging.info(f"Cursor object: {cursor_tac}")
                        
                        tactic = tactic_id + ' (' + next(cursor_tac) + ')'
                        logging.info(f"Tactic: {tactic}")
                        logging.info("Will append the tactic and data to the table_list.")
                        table_list.append({tactic:data})
                        break
        logging.info("Returned from the loop. Back in create_table method.")
        logging.info(f"Will write Table list to file: {table_list}")
        with open('/shared/table_List.txt', 'a') as out_file:
            for item in table_list: # item is json object with the contents for an item in the priority table.
                out_file.write(str(item) + "\n")
            out_file.write("\n")
            out_file.close() #  They are in the correct order
        logging.info("Table list written to ./shared/table_List.txt.")

        # creates and adds the json objects to the file
        logging.info("Will write the table_list to the needed_controls.json file.")
        with open('needed_controls.json', 'w') as out_file:
            json.dump(table_list, out_file, indent=2)
        logging.info("Table list written to ./needed_controls.json.")
        
        # creates html table by using the json file that just generated
        logging.info("Will open needed_controls.json file and read the contents.")
        with open('needed_controls.json', 'r') as out_file:
            logging.info("Opened needed_controls.json file.")
            json_objects = json.load(out_file)
            logging.info("Created json_objects from the needed_controls.json file using json.load.")
            logging.info(f"Logging json objects: {json_objects}")
            logging.info("Will write the json objects to the json_objects.txt file.")
            with open('/shared/json_objects.txt', 'a') as objectsFile:
                logging.info("Opened json_objects.txt file.")
                logging.info("Will write the json objects to the file.")
                for item in json_objects: # item is json object with the contents for an item in the priority table.
                    objectsFile.write(str(item) + "\n")
                objectsFile.write("\n")
                objectsFile.close() #  They are in the correct order
            logging.info("json_objects.txt file written to ./shared.")
            # Delete the file if it exists
            '''if os.path.exists('/app/templates/table.html'):
                os.remove('/app/templates/table.html')
                f = open('/shared/debug_input.txt', 'a')
                f.write('File deleted\n')
                f.close()'''
            # GEt current working directory
            logging.info("Will get the current working directory.")
            curDir = os.getcwd()
            logging.info(f"Current working directory, about to open /app/templates/table.html: {curDir}")
            # Log contents of the ./app/templates directory
            logging.info(f"Contents of /app/templates: {os.listdir('./app/templates')}")
            with open('./app/templates/table.html', 'w') as control_html:
                table_detail = '<ul><li>Static code analysis has revealed that the system has weaknesses or vulnerabilities.</li><li>'\
                            + 'Weaknesses and vulnerabilities are identified by their CWE or CVE IDs.</li><li>'\
                            + 'Each finding is followed by the MITRE ATT&CK technique that can be used to exploit it.</li><li>'\
                            + 'The MITRE ATT&CK tactic (i.e., the attack stage) that an adversary may complete by exploiting '\
                            + 'the weakness or vulnerability is given on the left panel.'\
                            + '</li><li>Also shown are the set of NIST SP 800-53 rev.5 security controls '\
                            + 'suggested to mitigate the system\'s exposure to the specified attack technique.'\
                            + '</li><li>Note that a single weakness or vulnerability may be mapped to more than one ATT&CK Tactic or Technique. '\
                            + 'In such cases, there will be more than one table entry for the particular CWE or CVE. '\
                            + 'The suggested security controls may be similar, but make sure to verify as the different attack '\
                            + 'techniques may require different security controls.</li></ul>'
                
                table_head = '<head>\
        <!-- Required meta tags -->\
        <meta charset="utf-8">\
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">\
        <!-- Bootstrap CSS -->\
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/css/bootstrap.min.css" integrity="sha384-TX8t27EcRE3e/ihU7zmQxVncDAy5uIKz4rEkgIXeMed4M0jlfIDPvg6uqKI2xXr2" crossorigin="anonymous">\
        </head>'


                 

                control_html.write(table_head + '<h1>Table</h1><div>' + table_detail + '</div><style>body {background-color: #FFFFFF; color: black;}h1 '
                                + '{text-align: center;} div {text-align: center;} ul {display: '
                                + 'inline-block; text-align: left;}</style>')
                for obj in json_objects:
                    build_direction = "LEFT_TO_RIGHT"
                    table_attributes = {"width": 100, "align" : "center", "border": 1}
                    html = json2table.convert(obj, build_direction=build_direction, 
                                            table_attributes=table_attributes)
                    control_html.write(html)
        # log the contents of the ./app/templates/table.html file
        # open the file
        logging.info("Will open the table.html file and read the contents.")
        with open('./app/templates/table.html', 'r') as file:
            file_contents = file.read()
        logging.info("Opened the table.html file.")
        logging.info(f"Contents of the table.html file: {file_contents}")
        # close the file
        file.close()
        logging.info("Closed the table.html file.")

    # creates a network flow graph
    def makeAttackPathsGraph(self, graph, tacticsOnlyGraph):
        logging.info("Enterred makeAttackPathsGraph method.")
        logging.info("Will create a networkx directed graph for the attack paths and store it in a local variable called attackPathsGraph.")
        attackPathsGraph= nx.DiGraph()
        logging.info("Initialized attackPathsGraph local variable. This is a networkx digraph.")
        SRC = 'source[s]' # starting point of the graph
        logging.info(f"Starting point in the graph is SRC: {SRC}")
        SINK = 'sink[t]' # ending point of the graph
        logging.info(f"Ending point in the graph is SINK: {SINK}")

        nodes = [[SRC]] # starting node
        logging.info(f"Nodes in the paths graph: {nodes}")
        logging.info("Will iterate through the tacticsOnlyGraph. For each node in the graph, we will get the techniques that are connected to the node.")
        for n in tacticsOnlyGraph.__iter__(): # gets tactic in order of path
            logging.info(f"Node in tacticsOnlyGraph: {n}")
            tech = []
            logging.info("Declared tech list.")
            logging.info("Will get the neighbors of the node.")
            neighbors = self.tacticsAndTechniquesGraph.neighbors(n)
            logging.info(f"Neighbors of {n}: {neighbors}")
            logging.info("Will iterate through the neighbors. For each neighbor in the neighbors, we will get the techniques.")
            for node in neighbors: # loops to get all techniques
                logging.info(f"Node in neighbors: {node}")
                logging.info("Checking if the node is a technique.")
                if 'technique' in node:
                    logging.info("Node is a technique.")
                    logging.info("Will append the node to the tech list.")
                    tech.append(n.split('/')[-1] + '/' + node.split('/')[-1]) # assigns unique name
            logging.info("Will append the tech list to the nodes list.")
            nodes.append(tech)
        logging.info("Returned from the loop. Back in makeAttackPathsGraph method.")
        logging.info("Will append the ending node to the nodes list.")
        nodes.append([SINK]) # ending node
        logging.info(f"Nodes in the paths graph: {nodes}")

        # adds nodes and edges to the network flow graph
        logging.info("Will iterate through the nodes. For each node in the nodes, we will add the node to the attackPathsGraph.")
        for i in range(len(nodes)-1):
            for j in range(len(nodes[i])):
                logging.info(f"Node in nodes: {nodes[i][j]}")
                logging.info("Will add the node to the attackPathsGraph.")
                attackPathsGraph.add_node(nodes[i][j])

                # checks what capacity to set
                if nodes[i][j] == 'source[s]':
                    capa = len(nodes[i+1])
                else:
                    capa = len(nodes[i])
                for k in range(len(nodes[i+1])):
                    logging.info("Will add the edge to the attackPathsGraph.")
                    attackPathsGraph.add_edge(nodes[i][j], nodes[i+1][k], capacity=capa, title=capa)
        logging.info(f"Nodes in the attack paths graph: {attackPathsGraph.nodes}")
        logging.info(f"Edges in the attack paths graph: {attackPathsGraph.edges}")
        logging.info("Will return the attackPathsGraph.")
        return attackPathsGraph


    def create_vulntable(self):
        logging.info("Enterred create_vulntable method.")
        # creates html table by using the json file that just generated
        logging.info("Will open the calledVulnerableFunctionsObjectList.txt file and read the contents.")
        with open('./app/artifacts/calledVulnerableFunctionsObjectList.txt', 'r') as out_file:
            logging.info("Opened calledVulnerableFunctionsObjectList.txt file.")
            functionsData = out_file.read()
            logging.info("Read the contents of the file into the functionsData variable.")
            functionsData = functionsData.split('\n') # List of strings
            logging.info("Split the contents of the file by newline.")
            json_objects = []
            logging.info("Declared json_objects list.")
            logging.info("Will iterate through the functionsData. For each data in the list, we will append the data to the json_objects list.")
            for data in functionsData:
                logging.info(f"Data item in functionsData: {data}")
                if data != '':
                    logging.info("Data item is not empty.")
                    logging.info("Will append the data to the json_objects list.")
                    json_objects.append(eval(data))
            
            logging.info("Returned from the loop. Back in create_vulntable method. Will write the json_objects to the ./app/templates/vulntable.json file.")
            with open('./app/templates/vulntable.html', 'w') as control_html:
                table_detail = '<ul><li>Code analysis has revealed that the system has the '\
                            + 'vulnerabilities identified by their CWE ids.</li><li>Each vulnerability'\
                            + ' found is followed by the file, function and line where it occurs. '\
                            + '</li></ul>'
                
                table_head = '<head>\
        <!-- Required meta tags -->\
        <meta charset="utf-8">\
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">\
        <!-- Bootstrap CSS -->\
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/css/bootstrap.min.css" integrity="sha384-TX8t27EcRE3e/ihU7zmQxVncDAy5uIKz4rEkgIXeMed4M0jlfIDPvg6uqKI2xXr2" crossorigin="anonymous">\
        </head>'

                
                control_html.write(table_head + '<h1>Table</h1><div>' + table_detail + '</div><style>body {background-color: #FFFFFF; color: black;}h1 '
                                + '{text-align: center;} div {text-align: center;} ul {display: '
                                + 'inline-block; text-align: left;}</style>')
                for obj in json_objects:
                    build_direction = "LEFT_TO_RIGHT"
                    table_attributes = {"width": 100, "align" : "center", "border": 1}
                    html = json2table.convert(obj, build_direction=build_direction, 
                                            table_attributes=table_attributes)
                    control_html.write(html)
        # log the contents of the ./app/templates/vulntable.html file
        # open the file
        logging.info("Will open the vulntable.html file and read the contents.")
        with open('./app/templates/vulntable.html', 'r') as file:
            file_contents = file.read()
        logging.info("Opened the vulntable.html file.")
        logging.info(f"Contents of the vulntable.html file: {file_contents}")
        # close the file
        file.close()
        logging.info("Closed the vulntable.html file.")



def main():
    logging.info("")
    logging.info("")
    logging.info("")
    logging.info("cwe_cve_to_techniques.py has started.")
    curDir = os.getcwd()
    logging.info("Initializing DatabaseConnection object")
    DBConnection = DatabaseConnection()
    logging.info("DatabaseConnection object initialized.")
    logging.info("Initializing ControlPriolitization object. Passing a DBConnection object to the constructor.")
    control_prioritization_instance = ControlPrioritization(DBConnection)
    logging.info("ControlPrioritization object initialized")
    logging.info("Initializing CreateVisualizations object.")
    visualizationsObject = CreateVisualizations()
    logging.info("CreateVisualizations object intialized.")
    logging.info("Creating Match_VulnerabilitesAndWeakness_ToAttackTactics_AndTechniques object.")
    matcherFindingsToTechniques = Match_VulnerabilitesAndWeakness_ToAttackTactics_AndTechniques(curDir, DBConnection, control_prioritization_instance, visualizationsObject)
    logging.info("Match_VulnerabilitesAndWeakness_ToAttackTactics_AndTechniques object created.")
    logging.info("")
    logging.info("")
    logging.info("All objects have been initialized.")
    logging.info("")
    logging.info("")
    logging.info("Running makeMatch() method of Match_VulnerabilitesAndWeakness_ToAttackTactics_AndTechniques object.")
    matcherFindingsToTechniques.makeMatch()
    logging.info("Returned from makeMatch() method. Back in main function.")
    # Copy the graph.html file to the shared directory
    os.system('cp ./app/templates/graph.html /shared')
    # confirm the file was copied
    logging.info("")
    logging.info("Check if the graph.html file was copied to the shared directory.")
    os.system('ls -la /shared/graph.html')

    # Copy the network_flow.html file to the shared directory
    os.system('cp ./app/templates/network_flow.html /shared')
    # confirm the file was copied
    logging.info("")
    logging.info("Check if the netowrk_flow.html file was copied to the shared directory.")
    os.system('ls -la /shared/network_flow.html')

    # Copy the table.html file to the shared directory
    os.system('cp ./app/templates/table.html /shared')
    # confirm the file was copied
    logging.info("")
    logging.info("Check if the table.html file was copied to the shared directory.")
    os.system('ls -la /shared/table.html')

    # check if the vulntable.html exists
    if os.path.exists('./app/templates/vulntable.html'):
        logging.info("The vulntable.html file exists.")
        # Copy the vulntable.html file to the shared directory
        os.system('cp ./app/templates/vulntable.html /shared')
        # confirm the file was copied
        logging.info("")
        logging.info("Check if the vulntable.html file was copied to the shared directory.")
        os.system('ls -la /shared/vulntable.html')
    else:
        logging.error("The vulntable.html file does not exist.")
    

    logging.info('Finished running the create graphs program.')
    
if __name__ == '__main__':
    main()