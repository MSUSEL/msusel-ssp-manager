import json
import os.path
from arango.client import ArangoClient
import networkx as nx
from pyvis import network as net
import os
import json2table

class DatabaseConnection:
    def __init__(self):
        self.client = ArangoClient()
        self.db = self.client.db('BRON', username='root', password='changeme')
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
            + 'filter tac.original_id == @userSelectedTactic '\
            + 'return tac._id'
   
    def determineAttackTechniquesNotMitigated(self, cursorTechniquesAndFindings, implemented_controls_dictionary_list):
        for singleTechniqueFindingDictionary in cursorTechniquesAndFindings:
            controlsToMitigateTechniques = [] # stores control that map to the specific technique
            techniquesAndFindingsList = list(singleTechniqueFindingDictionary.values())
            techniqueMappedToFinding = techniquesAndFindingsList[0]
            
            '''Una tecnica nueva que no hemos incluido en las listas al final. Vamos a tech-control collection,
            e iteramos por los edges e identificamos el cotnrol. Metemos el control en una lista.
            Chequeamos todos los controles implementados contra esa lista. Si el control es nuevo,
            METEMOS LA TECNICA en la lista.'''
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
        vulnerabilities_file = open(self.security_findings_file_path, 'r') 
        self.security_findings_dictionary_list = json.load(vulnerabilities_file)
        vulnerabilities_file.close()
        controls_file = open(self.controls_file_path, 'r')
        self.implemented_controls_dictionary_list = json.load(controls_file) # Ex: [{'control': 'CM-7'}, {'control': 'SC-7'}]
        controls_file.close()

    def weaknessOrVulnerability(self):
        is_cveList = self.security_findings_dictionary_list[0].get('cve', None)
        is_cweList = self.security_findings_dictionary_list[0].get('cwe', None)
        if is_cveList is not None:  
            self.findAttackTechniques(self.security_findings_dictionary_list, self.implemented_controls_dictionary_list, is_cveList)
        elif is_cweList is not None: 
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
        self.cursor = self.mapFindingstoMITREAttackTechniques(self.findings_list, finding_type)
        self.controlPrioritizationWrapperFunction(implemented_controls_dictionary_list, self.cursor, self.ControlPrioritization)

    def controlPrioritizationWrapperFunction(self, implemented_controls_dictionary_list, cursorTechniquesAndFindings, ControlPrioritization):
        ControlPrioritization.determineAttackTechniquesNotMitigated(cursorTechniquesAndFindings, implemented_controls_dictionary_list)
        query = ControlPrioritization.priorityControlsQuery
        bind_var = {'attackTechniquesUsableAgainstSecurityFindings': ControlPrioritization.attackTechniquesUsableAgainstSecurityFindings}
        cursorTechniquesAndControls = self.DBConnection.db.aql.execute(query, bind_vars=bind_var, ttl=300)

        ControlPrioritization.buildRecommendationsTableData(cursorTechniquesAndControls)

        query = ControlPrioritization.tacticToTechniqueQuery
        bind_vars = {'attackTechniquesUsableAgainstSecurityFindings': ControlPrioritization.attackTechniquesUsableAgainstSecurityFindings}
        cursorTacticToTechnique = self.DBConnection.db.aql.execute(query, bind_vars=bind_vars)

        with open('/shared/input.txt', 'r') as in_txt:
            userSelectedTactic = in_txt.read()
              
        query = ControlPrioritization.getTacticIDForUserSelectionQuery
        bind_vars = {'userSelectedTactic': userSelectedTactic}
        cursorUserTacticID = self.DBConnection.db.aql.execute(query, bind_vars=bind_vars)

        userSelectedTactic_id = ''
        for tactic_id in cursorUserTacticID:
            userSelectedTactic_id = tactic_id
        
        self.CreateVisualizations.make_graph(self.DBConnection.db, cursorTacticToTechnique, ControlPrioritization.recommendationsTableData, userSelectedTactic_id)



class CreateVisualizations:
    def __init__(self):
        self.tacticsList = []
        self.tacticsAndTechniquesGraph = nx.Graph()
        self.tacticsOnlyGraph = nx.DiGraph()
        self.pyvisTacticsAndTechniquesGraph = net.Network(height='100vh', width='100%', notebook=True, bgcolor=212121, font_color="white")
        self.pyvisAttackPathsGraph = net.Network(height='100vh', width='100%', notebook=True, bgcolor=212121, font_color="white")
        self.user_priority_tactic = None
        
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

    def checkIfUserPriorityWasDetected(self, userSelectedTactic_id):
        if userSelectedTactic_id in self.tacticsList:
            self.user_priority_tactic = userSelectedTactic_id

    def createPyvisTacticsAndTechniquesGraph(self):
        # translates networkx graph into PyViz graph
        self.pyvisTacticsAndTechniquesGraph.from_nx(self.tacticsAndTechniquesGraph)
        self.pyvisTacticsAndTechniquesGraph.force_atlas_2based()
        self.pyvisTacticsAndTechniquesGraph.show('/templates/graph.html')

    def createPyvisAttackPathsGraph(self, attackPathsGraph):
        # translates networkx graph into PyViz graph
        self.pyvisAttackPathsGraph.from_nx(attackPathsGraph)
        self.pyvisAttackPathsGraph.force_atlas_2based()
        self.pyvisAttackPathsGraph.show('/templates/network_flow.html')

    def make_graph(self, db, cursorTacticToTechnique, recommendationsTableData, userSelectedTactic_id):
        tacticToTacticEdgeCollection = db.collection('TacticTactic')

        self.addNodesAndEdgesToTacticsAndTechniquesGraph(cursorTacticToTechnique)
        self.addEdgesToTacticsAndTechniquesGraph(tacticToTacticEdgeCollection)
        self.checkIfUserPriorityWasDetected(userSelectedTactic_id)

        prioritize_lists = self.show_prioritize(self.user_priority_tactic) # runs algorithm that finds the prioritized paths
        self.create_table(db, prioritize_lists, recommendationsTableData)
        
        # Check if vulnerability effectiveness analysis has been run
        if os.path.exists('/artifacts/calledVulnerableFunctionsObjectList.txt'):
            self.create_vulntable() # If so, show functions in the dependencies that are called.
        
        attackPathsGraph = self.makeAttackPathsGraph(self.tacticsAndTechniquesGraph, self.tacticsOnlyGraph)

        self.createPyvisTacticsAndTechniquesGraph()
        self.createPyvisAttackPathsGraph(attackPathsGraph)


    # method to sort the individual priority lists
    def sort_list(self, a_list):
        return sorted(a_list, key=lambda tup: tup[1], reverse=False)  # lambda arguments : expression


    # finds priority of tactic
    def show_prioritize(self, user_priority_tactic):
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

                # if the tactic is the one that user specified make it the most prioritize node
                if user_priority_tactic != None and user_priority_tactic in node:
                    high.append((node, 0))
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
        # sort the individual lists
        low = self.sort_list(low)
        mid = self.sort_list(mid)
        high = self.sort_list(high)

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

        # loop to find the technique that maps to the specific tactic
        for obj in prioritize_lists:
            tactic_id = obj[0]

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

        # creates and adds the json objects to the file
        with open('needed_controls.json', 'w') as out_file:
            json.dump(table_list, out_file, indent=2)
        
        # creates html table by using the json file that just generated
        with open('needed_controls.json', 'r') as out_file:
            json_objects = json.load(out_file)
            with open('/templates/table.html', 'w') as control_html:
                table_detail = '<ul><li>Code analysis has revealed that the system has the '\
                            + 'vulnerabilities identified by their CVE ids.</li><li>Each vulnerability'\
                            + ' found is followed by the attack technique that can be used to exploit '\
                            + 'that vulnerability.</li><li>The attack stage id that an adversary could'\
                            + ' achieve by exploiting the vulnerability with the attack technique is '\
                            + 'given on the left.</li><li>Also shown are the set of security controls '\
                            + 'suggested to mitigate the system\'s exposure to the specified attack '\
                            + 'technique.</li></ul>'
                
                table_head = '<head>\
        <!-- Required meta tags -->\
        <meta charset="utf-8">\
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">\
        <!-- Bootstrap CSS -->\
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/css/bootstrap.min.css" integrity="sha384-TX8t27EcRE3e/ihU7zmQxVncDAy5uIKz4rEkgIXeMed4M0jlfIDPvg6uqKI2xXr2" crossorigin="anonymous">\
        </head>'


                table_navigation_bar = '<nav class="navbar navbar-expand-md navbar-dark bg-dark">\
        <a class="navbar-brand" href="#">SSP Manager</a>\
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">\
            <span class="navbar-toggler-icon"></span>\
        </button>\
        <div class="collapse navbar-collapse" id="navbarNav">\
            <ul class="navbar-nav mr-auto">\
                <li class="nav-item active">\
                    <a class="nav-link" href="#">Home <span class="sr-only">(current)</span></a>\
                </li>\
                <li class="nav-item">\
                    <a class="nav-link" href="#">Results</a>\
                </li>\
            </ul>\
            <ul class="navbar-nav">\
                <li class="nav-item">\
                    <a class="nav-link" href="#">Login</a>\
                </li>\
                <li class="nav-item">\
                    <a class="nav-link" href="#">Register</a>\
                </li>\
            </ul>\
        </div>\
        </nav>'

                control_html.write(table_head + table_navigation_bar + '<h1>Table</h1><div>' + table_detail + '</div><style>body {background-color: #212121; color: white;}h1 '
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

        # prepares unique nodes for the graph
        nodes = [[SRC]] # starting node
        for n in tacticsOnlyGraph.__iter__(): # gets tactic in order of path
            tech = []
            neighbors = self.tacticsAndTechniquesGraph.neighbors(n)
            for node in neighbors: # loops to get all techniques
                if 'technique' in node:
                    tech.append(n.split('/')[-1] + '/' + node.split('/')[-1]) # assigns unique name
            nodes.append(tech)
        nodes.append([SINK]) # ending node

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
        with open('./artifacts/calledVulnerableFunctionsObjectList.txt', 'r') as out_file:
            functionsData = out_file.read()
            functionsData = functionsData.split('\n') # List of strings
            json_objects = []
            for data in functionsData:
                if data != '':
                    json_objects.append(eval(data))
            with open('/templates/vulntable.html', 'w') as control_html:
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

                table_navigation_bar = '<nav class="navbar navbar-expand-md navbar-dark bg-dark">\
        <a class="navbar-brand" href="#">SSP Manager</a>\
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">\
            <span class="navbar-toggler-icon"></span>\
        </button>\
        <div class="collapse navbar-collapse" id="navbarNav">\
            <ul class="navbar-nav mr-auto">\
                <li class="nav-item active">\
                    <a class="nav-link" href="#">Home <span class="sr-only">(current)</span></a>\
                </li>\
                <li class="nav-item">\
                    <a class="nav-link" href="#">Results</a>\
                </li>\
            </ul>\
            <ul class="navbar-nav">\
                <li class="nav-item">\
                    <a class="nav-link" href="#">Login</a>\
                </li>\
                <li class="nav-item">\
                    <a class="nav-link" href="#">Register</a>\
                </li>\
            </ul>\
        </div>\
        </nav>'

                control_html.write(table_head + table_navigation_bar + '<h1>Table</h1><div>' + table_detail + '</div><style>body {background-color: #212121; color: white;}h1 '
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
    
if __name__ == '__main__':
    main()