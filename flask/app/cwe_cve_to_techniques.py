import json
import os.path
from arango.client import ArangoClient
import networkx as nx
from pyvis import network as net
import os
import json2table
import logging

logging.basicConfig(level=logging.INFO)

class DatabaseConnection:
    def __init__(self):
        arango_url = os.getenv('ARANGO_DB_URL', 'http://brondb:8529')
        arango_db_name = os.getenv('ARANGO_DB_NAME', 'BRON')
        arango_username = os.getenv('ARANGO_DB_USERNAME', 'root')
        arango_password = os.getenv('ARANGO_DB_PASSWORD', 'changeme')

        self.client = ArangoClient(hosts=arango_url)
        self.db = self.client.db(arango_db_name, username=arango_username, password=arango_password)
        self.techniqueControlCollection = self.db.collection('TechniqueControl')
        self.tacticToTacticEdgeCollection = self.db.collection('TacticTactic')

    
class ControlPrioritization:
    def __init__(self, DatabaseConnection): 
        self.attackTechniquesUsableAgainstSecurityFindings = [] # DB holds Attack Technique ids as 'technique/technique_00030', for example.
        self.attackTechniqueIDsAndListOfMatchedFindings = []
        self.DBConnection = DatabaseConnection
        # query to get the data for html table  
        self.priorityControlsQuery = 'for tech in technique '\
                + 'filter tech._id in @attackTechniquesUsableAgainstSecurityFindings '\
                + 'for tech_ctrl in TechniqueControl '\
                + 'filter tech_ctrl._from == tech._id '\
                + 'for ctrl in control '\
                + 'filter ctrl._id == tech_ctrl._to '\
                + 'collect tech_id=tech._id, tech_name=tech.name into ctrl=ctrl.id_name '\
                + 'return distinct {tech_id: tech_id, tech_name: tech_name, ctrl: unique(ctrl)}'
        self.recommendationsTableData = []
        self.tacticToTechniqueQuery = 'for item in @attackTechniquesUsableAgainstSecurityFindings ' \
            + 'for e, v, p in 1..2 inbound ' \
            + 'item TacticTechnique ' \
            + 'return { From: v._from, To: v._to }'
        self.getTacticIDForUserSelectionQuery = 'for tac in tactic '\
            + 'filter tac.original_id == @userSelectedMITRETacticID '\
            + 'return tac._id'
   
    def determineAttackTechniquesNotMitigated(self, cursorTechniquesAndFindings, implemented_controls_dictionary_list):
        for singleTechniqueFindingDictionary in cursorTechniquesAndFindings:
            controlsToMitigateTechniques = [] # stores control that map to the specific technique
            techniquesAndFindingsList = list(singleTechniqueFindingDictionary.values())
            techniqueMappedToFinding = techniquesAndFindingsList[0]
            
            '''A new technique that we haven't included in the final lists. We will go to the tech-control collection,
            iterate through the edges, and identify the control. We will add the control to a list.
            We will check all implemented controls against that list. If the control is new,
            we will ADD THE TECHNIQUE to the list.'''
            if techniqueMappedToFinding not in self.attackTechniquesUsableAgainstSecurityFindings:
                for techniqueControlEdge in self.DBConnection.techniqueControlCollection: # Tech-control edge collection
                    if techniqueControlEdge['_from'] == techniqueMappedToFinding:
                        controlsToMitigateTechniques.append(techniqueControlEdge['_to'])
                #Para cada control en control_dict_list, #check si es igual al control que acabamos de decir que es necesario.
                #Si ya  esta, no metemos la tecnica en la lista.
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
        return self.attackTechniquesUsableAgainstSecurityFindings,self.attackTechniqueIDsAndListOfMatchedFindings

    def buildRecommendationsTableData(self, cursorTechniquesAndControls):
        for techniqueControlDict in cursorTechniquesAndControls:
            tech_id = techniqueControlDict['tech_id']
            for techniqueAndFindingsList in self.attackTechniqueIDsAndListOfMatchedFindings:
                if tech_id == techniqueAndFindingsList[0]:
                    finding = 'cwe'
                    if 'cve' in techniqueAndFindingsList[1][0].lower():
                            finding = 'cve'
                    table_item = {finding: techniqueAndFindingsList[1],'Technique ID': tech_id, 'Technique Name': techniqueControlDict['tech_name']} 
                    table_item = table_item | {'Control (Name)': techniqueControlDict['ctrl']}
                    self.recommendationsTableData.append(table_item)
        

class Match_VulnerabilitesAndWeakness_ToAttackTactics_AndTechniques:
    def __init__(self, curDir, DatabaseConnection, ControlPrioritization, CreateVisualizations):
        self.security_findings_file_path = os.path.join(curDir, "/shared", 'vulnerabilities.json')
        self.controls_file_path = os.path.join(curDir, "/shared", 'controls.json')
        self.implemented_controls_dictionary_list = []
        self.security_findings_dictionary_list = []
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
        # Query to get the techniques that are related to the CWEs in the findings_list.
        self.attacksAgainstCWEsQuery = 'for cwe in cwe '\
            + 'filter cwe.original_id in @cwe_list '\
            + 'for capec_cwe in CapecCwe '\
            + 'filter capec_cwe._to == cwe._id '\
            + 'for tc in TechniqueCapec '\
            + 'filter tc._to == capec_cwe._from '\
            + 'collect tech=tc._from into cwe_id=cwe.original_id '\
            + 'return {tech:tech, cwe:unique(cwe_id)}'
        self.findings_list = []
        self.cursor = None
        self.DBConnection = DatabaseConnection
        self.ControlPrioritization = ControlPrioritization
        self.CreateVisualizations = CreateVisualizations

    def makeMatch(self):
        self.createDictionaryListsFromInputFiles()
        self.weaknessOrVulnerability()
        
    def createDictionaryListsFromInputFiles(self):
        security_findingsFile = open(self.security_findings_file_path, 'r') 
        self.security_findings_dictionary_list = json.load(security_findingsFile)
        security_findingsFile.close()
        logging.info(f"Security findings dictionary list: {self.security_findings_dictionary_list}")    
        controls_file = open(self.controls_file_path, 'r')
        self.implemented_controls_dictionary_list = json.load(controls_file) # Ex: [{'control': 'CM-7'}, {'control': 'SC-7'}]
        controls_file.close()
        logging.info(f"Implemented controls dictionary list: {self.implemented_controls_dictionary_list}")

    def weaknessOrVulnerability(self):
        is_cveList = self.security_findings_dictionary_list[0].get('cve', None)
        is_cweList = self.security_findings_dictionary_list[0].get('cwe', None)
        if is_cveList is not None: 
            logging.info('CVE list detected') 
            self.findAttackTechniques(self.security_findings_dictionary_list, self.implemented_controls_dictionary_list, is_cveList)
        elif is_cweList is not None: 
            logging.info('CWE list detected')
            self.findAttackTechniques(self.security_findings_dictionary_list, self.implemented_controls_dictionary_list, is_cweList)
        else:
            print('Invalid (not \'cve\'/\'cwe\') item detected from the input json file')

    def createFindingsList(self, security_findings_dictionary_list):
        findings_list = []
        for dict in security_findings_dictionary_list:
            for value in dict.values():
                findings_list.append(value)
        return findings_list 
    
    def mapFindingstoMITREAttackTechniques(self, findings_list, finding_type):
        if 'CVE' in finding_type:
            query = self.attacksAgainstCVEsQuery
            # Specify that @cve_list in the query is cve_list.
            bind = {'cve_list': findings_list}
        else: # CWE case
            query = self.attacksAgainstCWEsQuery
            # Specify that @cwe_list in the query is cwe_list.
            bind = {'cwe_list': findings_list}
        # Execute the query.
        return self.DBConnection.db.aql.execute(query, bind_vars=bind, ttl=300)

    def findAttackTechniques(self, security_findings_dictionary_list, implemented_controls_dictionary_list, finding_type):
        self.findings_list = self.createFindingsList(security_findings_dictionary_list)
        logging.info(f"Findings list: {self.findings_list}")
        self.cursor = self.mapFindingstoMITREAttackTechniques(self.findings_list, finding_type)
        self.controlPrioritizationWrapperFunction(implemented_controls_dictionary_list, self.cursor, self.ControlPrioritization)

    def controlPrioritizationWrapperFunction(self, implemented_controls_dictionary_list, cursorTechniquesAndFindings, ControlPrioritization):
        ControlPrioritization.determineAttackTechniquesNotMitigated(cursorTechniquesAndFindings, implemented_controls_dictionary_list)
        query = ControlPrioritization.priorityControlsQuery
        bind_var = {'attackTechniquesUsableAgainstSecurityFindings': ControlPrioritization.attackTechniquesUsableAgainstSecurityFindings}
        cursorTechniquesAndControls = self.DBConnection.db.aql.execute(query, bind_vars=bind_var, ttl=300)

        ControlPrioritization.buildRecommendationsTableData(cursorTechniquesAndControls)
        logging.info(f"Recommendations table data: {ControlPrioritization.recommendationsTableData}")

        query = ControlPrioritization.tacticToTechniqueQuery
        bind_vars = {'attackTechniquesUsableAgainstSecurityFindings': ControlPrioritization.attackTechniquesUsableAgainstSecurityFindings}
        cursorTacticToTechnique = self.DBConnection.db.aql.execute(query, bind_vars=bind_vars)

        '''with open('/shared/input.txt', 'r') as in_txt:
            userSelectedMITRETacticID = in_txt.read()
              
        query = ControlPrioritization.getTacticIDForUserSelectionQuery
        bind_vars = {'userSelectedMITRETacticID': userSelectedMITRETacticID}
        cursorUserTacticID = self.DBConnection.db.aql.execute(query, bind_vars=bind_vars)'''

        # Store BRON tactic id
        userSelectedBRONTactic_id = ''
        '''for tactic_id in cursorUserTacticID:
            userSelectedBRONTactic_id = tactic_id'''
        
        self.CreateVisualizations.make_graph(self.DBConnection.db, cursorTacticToTechnique, ControlPrioritization.recommendationsTableData, userSelectedBRONTactic_id)



class CreateVisualizations:
    def __init__(self):
        self.tacticsList = []
        self.tacticsAndTechniquesGraph = nx.Graph()
        self.tacticsOnlyGraph = nx.DiGraph()
        self.pyvisTacticsAndTechniquesGraph = net.Network(height='100vh', width='100%', notebook=True, bgcolor="#FFFFFF", font_color="black")
        self.pyvisAttackPathsGraph = net.Network(height='100vh', width='100%', notebook=True, bgcolor="#FFFFFF", font_color="black")
        self.user_priority_BRONtacticID = None
        
    def addNodesAndEdgesToTacticsAndTechniquesGraph(self, cursorTacticToTechnique):
        for edge in cursorTacticToTechnique:
            tactic, technique = edge.items()
            self.tacticsAndTechniquesGraph.add_nodes_from([tactic[1], technique[1]])
            self.tacticsAndTechniquesGraph.add_edge(tactic[1], technique[1])
            self.tacticsList.append(tactic[1])

    def addEdgesToTacticsAndTechniquesGraph(self, tacticToTacticEdgeCollection):
        for edge in tacticToTacticEdgeCollection:
            if edge['_from'] in self.tacticsList and edge['_to'] in self.tacticsList:
                self.tacticsAndTechniquesGraph.add_edge(edge['_from'], edge['_to'])
                self.tacticsOnlyGraph.add_edge(edge['_from'], edge['_to'])
                # log the edges in the tactics only graph
                logging.info(f"Edges in the tactics only graph: {self.tacticsOnlyGraph.edges}")

    def checkIfUserPriorityWasDetected(self, userSelectedBRONTactic_id):
        if userSelectedBRONTactic_id in self.tacticsList:
            self.user_priority_BRONtacticID = userSelectedBRONTactic_id
            f = open('/shared/debug_input.txt', 'a')
            f.write('User selected tactic: ' + self.user_priority_BRONtacticID + '\n')
            f.close()

    def createPyvisTacticsAndTechniquesGraph(self):
        # translates networkx graph into PyViz graph
        self.pyvisTacticsAndTechniquesGraph.from_nx(self.tacticsAndTechniquesGraph)
        self.pyvisTacticsAndTechniquesGraph.force_atlas_2based()
        self.pyvisTacticsAndTechniquesGraph.show('./app/templates/graph.html')

    def createPyvisAttackPathsGraph(self, attackPathsGraph):
        # translates networkx graph into PyViz graph
        self.pyvisAttackPathsGraph.from_nx(attackPathsGraph)
        self.pyvisAttackPathsGraph.force_atlas_2based()
        self.pyvisAttackPathsGraph.show('./app/templates/network_flow.html')

    def make_graph(self, db, cursorTacticToTechnique, recommendationsTableData, userSelectedBRONTactic_id):
        tacticToTacticEdgeCollection = db.collection('TacticTactic')

        self.addNodesAndEdgesToTacticsAndTechniquesGraph(cursorTacticToTechnique)
        self.addEdgesToTacticsAndTechniquesGraph(tacticToTacticEdgeCollection)
        self.checkIfUserPriorityWasDetected(userSelectedBRONTactic_id)

        prioritize_lists = self.show_prioritize(self.user_priority_BRONtacticID) # runs algorithm that finds the prioritized paths
        self.create_table(db, prioritize_lists, recommendationsTableData)
        
        # Check if vulnerability effectiveness analysis has been run
        if os.path.exists('./app/artifacts/calledVulnerableFunctionsObjectList.txt'):
            self.create_vulntable() # If so, show functions in the dependencies that are called.
        
        # log the contents of the tacticsOnlyGraph
        logging.info(f"Nodes in the tactics only graph: {self.tacticsOnlyGraph.nodes}")
        attackPathsGraph = self.makeAttackPathsGraph(self.tacticsAndTechniquesGraph, self.tacticsOnlyGraph)

        self.createPyvisTacticsAndTechniquesGraph()
        self.createPyvisAttackPathsGraph(attackPathsGraph)


    # method to sort the individual priority lists
    def sort_list(self, a_list):
        return sorted(a_list, key=lambda tup: tup[1], reverse=False)  # lambda arguments : expression


    # finds priority of tactic
    def show_prioritize(self, user_priority_BRONtacticID):
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
        table_list = [] # will contain data for each table
        with open('/shared/prioritize_Lists.txt', 'a') as out_file:
            for item in prioritize_lists: # item is a tuple, tactic ID, and some munber.
                out_file.write(str(item) + "\n")
            out_file.write("\n")
            out_file.close() # They are in the correct order


        # loop to find the technique that maps to the specific tactic
        for obj in prioritize_lists:
            tactic_id = obj[0] # obj -> ('tactic/tactic_00008', 0), for ex

            # finds technique(s) that map from the specific tactic
            query = 'for tac_tech in TacticTechnique '\
                + 'filter tac_tech._from == @tac_id '\
                + 'return distinct tac_tech._to'
            
            bind_var = {'tac_id': tactic_id}
            cursor = db.aql.execute(query, bind_vars=bind_var)

            # checks whether the technique is in the graph
            for tech_id in cursor:
                for data in recommendationsTableData:
                    if tech_id == data['Technique ID']:
                        
                        query = 'for tac in tactic '\
                        + 'filter tac._id == @tactic_id '\
                        + 'return tac.name'
                    
                        bind_var = {'tactic_id': tactic_id}
                        cursor_tac = db.aql.execute(query, bind_vars=bind_var)
                        
                        tactic = tactic_id + ' (' + next(cursor_tac) + ')'
                        table_list.append({tactic:data})
                        break
        
        with open('/shared/table_List.txt', 'a') as out_file:
            for item in table_list: # item is json object with the contents for an item in the priority table.
                out_file.write(str(item) + "\n")
            out_file.write("\n")
            out_file.close() #  They are in the correct order

        # creates and adds the json objects to the file
        with open('needed_controls.json', 'w') as out_file:
            json.dump(table_list, out_file, indent=2)
        
        # creates html table by using the json file that just generated
        with open('needed_controls.json', 'r') as out_file:
            json_objects = json.load(out_file)
            with open('/shared/json_objects.txt', 'a') as objectsFile:
                for item in json_objects: # item is json object with the contents for an item in the priority table.
                    objectsFile.write(str(item) + "\n")
                objectsFile.write("\n")
                objectsFile.close() #  They are in the correct order
            # Delete the file if it exists
            '''if os.path.exists('/app/templates/table.html'):
                os.remove('/app/templates/table.html')
                f = open('/shared/debug_input.txt', 'a')
                f.write('File deleted\n')
                f.close()'''
            # GEt current working directory
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



    # creates a network flow graph
    def makeAttackPathsGraph(self, graph, tacticsOnlyGraph):
        attackPathsGraph= nx.DiGraph()
        SRC = 'source[s]' # starting point of the graph
        SINK = 'sink[t]' # ending point of the graph

        # log the nodes in the graph
        


        # prepares unique nodes for the graph
        nodes = [[SRC]] # starting node
        for n in tacticsOnlyGraph.__iter__(): # gets tactic in order of path
            tech = []
            neighbors = self.tacticsAndTechniquesGraph.neighbors(n)
            logging.info(f"Neighbors of {n}: {neighbors}")
            for node in neighbors: # loops to get all techniques
                if 'technique' in node:
                    tech.append(n.split('/')[-1] + '/' + node.split('/')[-1]) # assigns unique name
            nodes.append(tech)
        nodes.append([SINK]) # ending node

        # log the nodes in the graph
        logging.info(f"Nodes in the paths graph: {nodes}")

        # adds nodes and edges to the network flow graph
        for i in range(len(nodes)-1):
            for j in range(len(nodes[i])):
                attackPathsGraph.add_node(nodes[i][j])

                # checks what capacity to set
                if nodes[i][j] == 'source[s]':
                    capa = len(nodes[i+1])
                else:
                    capa = len(nodes[i])
                for k in range(len(nodes[i+1])):
                    attackPathsGraph.add_edge(nodes[i][j], nodes[i+1][k], capacity=capa, title=capa)
        
        return attackPathsGraph


    def create_vulntable(self):
        # creates html table by using the json file that just generated
        with open('./app/artifacts/calledVulnerableFunctionsObjectList.txt', 'r') as out_file:
            functionsData = out_file.read()
            functionsData = functionsData.split('\n') # List of strings
            json_objects = []
            for data in functionsData:
                if data != '':
                    json_objects.append(eval(data))
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



def main():
    curDir = os.getcwd()
    DBConnection = DatabaseConnection()
    control_prioritization_instance = ControlPrioritization(DBConnection)
    visualizationsObject = CreateVisualizations()
    matcherFindingsToTechniques = Match_VulnerabilitesAndWeakness_ToAttackTactics_AndTechniques(curDir, DBConnection, control_prioritization_instance, visualizationsObject)
    matcherFindingsToTechniques.makeMatch()
    # Copy the graph.html file to the shared directory
    os.system('cp ./app/templates/graph.html /shared')
    # Copy the network_flow.html file to the shared directory
    os.system('cp ./app/templates/network_flow.html /shared')
    # Copy the vulntable.html file to the shared directory
    os.system('cp ./app/templates/vulntable.html /shared')
    # Copy the table.html file to the shared directory
    os.system('cp ./app/templates/table.html /shared')
    logging.info('Finished running the create graphs program.')
    
if __name__ == '__main__':
    main()