import os
import json
import logging
from arango.client import ArangoClient
import networkx as nx
from pyvis import network as net
import json2table
from typing import List, Dict, Tuple, Any

# Initialize the logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
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
            logger.error(f"Failed to connect to ArangoDB: {e}")
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
            logger.error(f"Failed to execute AQL query: {e}") # e is the exception message.
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



def normalize_tactic_id(tactic_id: str) -> str:
    """Normalize tactic ID to match the edge format."""
    return tactic_id.replace('TA', 'tactic_')


class ControlPrioritization:
    def __init__(self):
        """Handles prioritization of controls for attack techniques."""
        self.attackTechniquesUsableAgainstSecurityFindings: List[str] = []
        self.attackTechniqueIDsAndListOfMatchedFindings: List[List[str]] = []

    def determine_unmitigated_techniques(
        self, cursor_techniques_and_findings: List[Dict[str, Any]], implemented_controls: List[Dict[str, str]]
    ) -> Tuple[List[str], List[List[str]]]:
        """
        Determine attack techniques not mitigated by implemented controls.
        """
        for technique_dict in cursor_techniques_and_findings:
            if debugging == True:
                logger.info(f"Technique dict: {technique_dict}")
            controls_to_mitigate = []
            technique_mapped_to_finding = list(technique_dict.values())[0]
            if debugging == True:
                logger.info(f"In determine_unmitigated, technique mapped to finding: {technique_mapped_to_finding}")

            # Normalize technique ID to match with edges
            normalized_technique = normalize_tactic_id(technique_mapped_to_finding)
            if debugging == True:
                logger.info(f"normalized technique: {normalized_technique}")
                logger.info(f"AttackTechniquesUsable: {self.attackTechniquesUsableAgainstSecurityFindings}")

            if normalized_technique not in self.attackTechniquesUsableAgainstSecurityFindings:
                controls_to_mitigate = technique_dict.get('controls', [])
                if debugging == True:
                    logger.info(f"Controls to mitigate: {controls_to_mitigate}")
                
                # Check if any of the controls are already implemented
                if not any(
                    f"control/{control['id']}" in controls_to_mitigate for control in implemented_controls
                ):
                    self.attackTechniquesUsableAgainstSecurityFindings.append(normalized_technique)
                    self.attackTechniqueIDsAndListOfMatchedFindings.append(list(technique_dict.values()))
        
        return self.attackTechniquesUsableAgainstSecurityFindings, self.attackTechniqueIDsAndListOfMatchedFindings

    def build_recommendations_table_data(
        self, cursor_techniques_and_controls: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Build data for the recommendations table based on techniques and controls.
        """
        recommendations_table_data = []
        
        for technique_control_dict in cursor_techniques_and_controls:
            tech_id = technique_control_dict['tech_id']
            for technique_and_findings in self.attackTechniqueIDsAndListOfMatchedFindings:
                if tech_id == technique_and_findings[0]:
                    finding_type = 'cwe' if 'cve' not in technique_and_findings[1][0].lower() else 'cve'
                    table_item = {
                        finding_type: technique_and_findings[1],
                        'Technique ID': tech_id,
                        'Technique Name': technique_control_dict['tech_name'],
                        'Control (Name)': technique_control_dict['ctrl']
                    }
                    recommendations_table_data.append(table_item)

        return recommendations_table_data


class MatchVulnerabilitiesAndWeaknessToAttackTacticsAndTechniques:
    def __init__(self, db_connection: DatabaseConnection, control_prioritization: ControlPrioritization, visualizer: 'CreateVisualizations'):
        """Coordinates the matching of vulnerabilities and techniques with tactics."""
        self.db_connection = db_connection
        self.control_prioritization = control_prioritization
        self.visualizer = visualizer
    
    def execute_queries_and_generate_recommendations(self, attack_techniques_findings: List[Dict[str, Any]], implemented_controls: List[Dict[str, str]]):
        """
        Execute queries to gather data and generate recommendations.
        """
        # Determine techniques not mitigated
        techniques, findings = self.control_prioritization.determine_unmitigated_techniques(
            attack_techniques_findings, implemented_controls
        )
        
        # Prepare AQL query
        priority_controls_query = self.control_prioritization.priorityControlsQuery
        bind_vars = {'attackTechniquesUsableAgainstSecurityFindings': techniques}
        cursor_techniques_and_controls = self.db_connection.execute_aql(priority_controls_query, bind_vars)
        
        # Build recommendations table
        recommendations_table = self.control_prioritization.build_recommendations_table_data(cursor_techniques_and_controls)
        
        # Prepare tactic to technique query
        tactic_to_technique_query = self.control_prioritization.tacticToTechniqueQuery
        cursor_tactic_to_technique = self.db_connection.execute_aql(tactic_to_technique_query, bind_vars)
        
        # Generate graphs and visualizations
        self.visualizer.create_visualizations(cursor_tactic_to_technique, recommendations_table)

        return recommendations_table



class CreateVisualizations:
    def __init__(self):
        """Handles the creation of visualizations using graphs."""
        self.tactics_list: List[str] = []
        self.tactics_and_techniques_graph = nx.Graph()
        self.tactics_only_graph = nx.DiGraph()
        self.pyvis_tactics_and_techniques_graph = net.Network(height='100vh', width='100%', notebook=True, bgcolor="#FFFFFF", font_color="black")
        self.pyvis_attack_paths_graph = net.Network(height='100vh', width='100%', notebook=True, bgcolor="#FFFFFF", font_color="black")

    def add_nodes_and_edges(self, cursor_tactic_to_technique: List[Dict[str, str]]):
        """Add nodes and edges to the tactics and techniques graph from cursor data."""
        for edge in cursor_tactic_to_technique:
            tactic_id = normalize_tactic_id(edge['_from'])
            technique_id = normalize_tactic_id(edge['_to'])
            
            logger.info(f"Adding nodes and edge: {tactic_id} -> {technique_id}")
            
            # Add nodes and edges
            self.tactics_and_techniques_graph.add_node(tactic_id)
            self.tactics_and_techniques_graph.add_node(technique_id)
            self.tactics_and_techniques_graph.add_edge(tactic_id, technique_id)
            self.tactics_list.append(tactic_id)

        logger.info(f"Nodes added: {self.tactics_and_techniques_graph.nodes}")
        logger.info(f"Edges added: {self.tactics_and_techniques_graph.edges}")

    def add_edges_to_tactics_graph(self, tactic_to_tactic_edges: List[Dict[str, str]]):
        """Add edges between tactics in the tactics-only graph."""
        for edge in tactic_to_tactic_edges:
            from_tactic = normalize_tactic_id(edge['_from'])
            to_tactic = normalize_tactic_id(edge['_to'])

            if from_tactic in self.tactics_list and to_tactic in self.tactics_list:
                logger.info(f"Adding edge to tactics-only graph: {from_tactic} -> {to_tactic}")
                self.tactics_only_graph.add_edge(from_tactic, to_tactic)
    
    def create_visualizations(self, cursor_tactic_to_technique: List[Dict[str, str]], recommendations_table: List[Dict[str, Any]]):
        """Create visualizations based on graph data and recommendations."""
        # Add nodes and edges for tactics and techniques
        self.add_nodes_and_edges(cursor_tactic_to_technique)

        # Add tactic-to-tactic edges
        self.add_edges_to_tactics_graph(self.tactics_list)  # Ensure edges match normalized IDs
        
        # Visualize the constructed graphs (e.g., using pyvis for web display)
        self.render_pyvis_graphs()

    def render_pyvis_graphs(self):
        """Render the pyvis graphs for visualization."""
        self.pyvis_tactics_and_techniques_graph.from_nx(self.tactics_and_techniques_graph)
        self.pyvis_attack_paths_graph.from_nx(self.tactics_only_graph)

        # Customize and save/display graphs as needed
        self.pyvis_tactics_and_techniques_graph.show("tactics_and_techniques.html")
        self.pyvis_attack_paths_graph.show("attack_paths.html")



def validate_controls_data(controls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Validate that each control has an 'id' key.
    Logs a warning for controls that are missing the key and returns a clean list.
    
    :param controls: List of control dictionaries to validate.
    :return: A list of valid control dictionaries that contain the 'id' key.
    """
    valid_controls = []
    for control in controls: # control are like this: {'control': 'CM-7'}
        if 'id' in control:
            valid_controls.append(control)
        else:
            logger.warning(f"Control without 'id' key found and skipped: {control}")
    return valid_controls



import ast

def load_data(cur_dir: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Load security findings, controls, and vulnerable functions data from files.
    
    :param cur_dir: The current directory to build file paths.
    :return: A tuple containing the security findings list, implemented controls list, and vulnerable functions list.
    """
    # Define file paths
    security_findings_file_path = os.path.join(cur_dir, "shared", 'vulnerabilities.json')
    controls_file_path = os.path.join(cur_dir, "shared", 'controls.json')
    vulnerable_functions_file_path = os.path.join(cur_dir, "app/artifacts", 'calledVulnerableFunctionsObjectList.txt')
    
    # Load security findings
    with open(security_findings_file_path, 'r') as file:
        security_findings_dictionary_list = json.load(file)

    # Load implemented controls
    with open(controls_file_path, 'r') as file:
        implemented_controls_dictionary_list = json.load(file)
    
    # Load vulnerable functions as Python dicts
    called_vulnerable_functions_list = []
    with open(vulnerable_functions_file_path, 'r') as file:
        for line in file:
            if line.strip():  # Skip empty lines
                try:
                    # Use literal_eval to safely parse the string as a Python dict
                    called_vulnerable_functions_list.append(ast.literal_eval(line.strip()))
                except (SyntaxError, ValueError) as e:
                    logger.warning(f"Could not parse line as dictionary: {line.strip()} - Error: {e}")

    # Validate controls data
    implemented_controls_dictionary_list = validate_controls_data(implemented_controls_dictionary_list)

    return security_findings_dictionary_list, implemented_controls_dictionary_list, called_vulnerable_functions_list




def main():
    # Current working directory or project root
    cur_dir = os.getcwd()
    
    # Initialize components
    db_connection = DatabaseConnection()
    query_service = DatabaseQueryService(db_connection)
    control_prioritization = ControlPrioritization()
    visualizer = CreateVisualizations()

    # Load input data. Returns security_findings_dictionary_list, implemented_controls_dictionary_list
    security_findings, implemented_controls, vulnerable_functions = load_data(cur_dir)
    if debugging == True:
        #logger.info(f"Findings dict: {security_findings}")
        #logger.info(f"Implemented controls dict: {implemented_controls}")
        logger.info(f"vulnerable_functions: {vulnerable_functions}")
        pass

    # Get techniques not mitigated
    unmitigated_techniques, matched_findings = control_prioritization.determine_unmitigated_techniques(
        security_findings, implemented_controls
    )
    if debugging == True:
        logger.info(f"Unmitigated techniques: {unmitigated_techniques}")
        logger.info(f"Matched findings: {matched_findings}")
        pass

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
