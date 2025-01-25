from flask import Blueprint, jsonify
import ast
import json
import logging
import os
import time
from .db_queries import DatabaseConnection, DatabaseQueryService
from .priority_controls import ManageData
import networkx as nx


attack_blueprint = Blueprint('attack', __name__)
logging.basicConfig(level=logging.INFO)
debugging = True

def listTechniquesForEachStage(tacticsAndTechniquesGraph, tacticsOriginalIDsList):
    attackPathGraph = [] # This is a list of lists, where each list contains the techniques for a given tactic


    debug_list = tacticsOriginalIDsList[0:1]
    logging.info(f"Debug list: {debug_list}")
    if debugging:
        logging.info("Enterred listTechniquesForEachStage method.")
        logging.info(f"tacticsOriginalIDsList: {tacticsOriginalIDsList}")
        logging.info("Will create a networkx directed graph for the attack paths and store it in a local variable called attackPathsGraph.")
        #List the edges in the tacticsOnlyGraph: [('tactic/tactic_00003', 'tactic/tactic_00005')]
        logging.info(f"Type of the tacticsAndTechniquesGraph: {type(tacticsAndTechniquesGraph)}")
        logging.info(f"List the nodes in the tacticsAndTechniquesGraph: {tacticsAndTechniquesGraph.nodes}")
        logging.info(f"List the edges in the tacticsAndTechniquesGraph: {tacticsAndTechniquesGraph.edges}")

    for tactic in tacticsOriginalIDsList:
    #for tactic in debug_list:
        if debugging:
            logging.info(f"Current tactic: {tactic}")
        logging.info(f"Current tactic: {tactic}")
        # Check if the tactic exists in the tacticsAndTechniquesGraph
        if f"tactic/{tactic}" in tacticsAndTechniquesGraph.nodes:
            # Get direct neighbors (connected nodes) in the tacticsAndTechniquesGraph
            connected_nodes = tacticsAndTechniquesGraph.neighbors(f"tactic/{tactic}")
            if debugging:
                logging.info(f"Connected nodes: {connected_nodes}")
           
            # Filter neighbors to get only techniques (nodes starting with "technique/")
            techniques = [node for node in connected_nodes if node.startswith('technique/')]
            logging.info(f"Techniques for the current tactic: {techniques}")
            # Prepend tactic to each element in techniques
            listWithTacticPrependend = []
            for element in techniques:
                element = f"{tactic}/{element}"
                listWithTacticPrependend.append(element)

            attackPathGraph.append(listWithTacticPrependend)
           
            # Print or process the tactic and its directly connected techniques
            #print(f"Tactic: {tactic}, Directly Connected Techniques: {techniques}")
    if debugging:
        logging.info(f"Attack path graph: {attackPathGraph}")
    logging.info(f"Attack path graph: {attackPathGraph}")
    return attackPathGraph # This is a list of lists, where each list contains the techniques for a given tactic


def createNetworkXGraph(listOfList):
    G = nx.DiGraph()
   
    # Add the start node
    G.add_node("start")
   
    # Connect start node to each element of the first list
    for element in listOfList[0]:
        G.add_edge("start", element)
   
    # Loop through the lists to connect elements from one list to the next
    for i in range(len(listOfList) - 1):
        for elem1 in listOfList[i]:
            for elem2 in listOfList[i + 1]:
                logging.info(f"i is {i}")
                logging.info(f"Connecting {elem1} to {elem2}")
                G.add_edge(elem1, elem2)
   
    # Connect elements of the last list to the end node
    for element in listOfList[-1]:
        G.add_edge(element, "end")
   
    # Add the end node to the graph
    G.add_node("end")
   
    return G

def convert_nx_to_vis_format(graph: nx.Graph):
    # Convert nodes
    nodes = [{"id": str(node), "label": str(node)} for node in graph.nodes()]
    # Convert edges
    edges = [{"from": str(source), "to": str(target)} for source, target in graph.edges()]
    # Combine nodes and edges
    vis_format = {"nodes": nodes, "edges": edges}
    return vis_format  # Do not stringify here, return as a Python dictionary

def convert2visNetworkFormat(initial):
    nodes = []
    edges = []
    node_id = 1
    node_map = {}
    for node in initial['nodes']:
        node_map[node['id']] = node_id
        if node_id == 1:
            nodes.append({'id': node_id, 'label': node['label'], 'color': {'background': '#CCE5FF', 'border': 'black'}})
        else:
            nodes.append({'id': node_id, 'label': node['label'], 'color': {'background': '#CCE5FF', 'border': 'black'}})
        node_id += 1
    for edge in initial['edges']:
        edges.append({'from': node_map[edge['from']], 'to': node_map[edge['to']]})
    return {'nodes': nodes, 'edges': edges}


@attack_blueprint.route('/attack_paths', methods=['GET','POST'])
def attacks():
    logging.info("Entered attacks method in attack_paths route.")
    # Current working directory or project root
    cur_dir = os.getcwd()
    logging.info(f"Current working directory: {cur_dir}")
   
    # Initialize components
    db_connection = DatabaseConnection()
    logging.info("Initialized database connection object.")
    query_service = DatabaseQueryService(db_connection)
    logging.info("Initialized database query service object.")

    logging.info("Will initialize data manager object. The attack_paths_graph DATA will be created during the initialization of the data manager object.")
    data_manager = ManageData(cur_dir, query_service)
    logging.info("")
    logging.info("")
   
    logging.info("Back from data manager object initialization. We're on the attacks method in the attack_paths route.")
    logging.info("Will pass data_manager.tacticsAndTechniquesGraph and data_manager.orderedTacticsPathOriginalIDs to listTechniquesForEachStage method.")
    listOfLists = listTechniquesForEachStage(data_manager.tacticsAndTechniquesGraph, data_manager.orderedTacticsPathOriginalIDs)
    logging.info(f"Liat of techniques for each stage. listOfLists: {listOfLists}")
    attack_paths_graph = createNetworkXGraph(listOfLists)
    logging.info(f"attack_paths_graph nodes: {attack_paths_graph.nodes}")
    logging.info(f"attack_paths_graph edges: {attack_paths_graph.edges}")


   
    # Combine nodes and edges into a single object
    graph_data = convert_nx_to_vis_format(attack_paths_graph)
    logging.info(f"attack_paths_graph nodes: {attack_paths_graph.nodes}")
    logging.info(f"attack_paths_graph edges: {attack_paths_graph.edges}")

    logging.info(f"Graph data: {graph_data}")

    # Example graph data
    '''nodes = [
        {'id': 1, 'label': 'Node 1', 'color': {'background': 'red', 'border': 'black'}},
        {'id': 2, 'label': 'Node 2', 'color': {'background': 'green', 'border': 'black'}},
        {'id': 3, 'label': 'Node 3', 'color': {'background': 'blue', 'border': 'black'}},
        {'id': 4, 'label': 'Node 4', 'color': {'background': 'yellow', 'border': 'black'}},
        {'id': 5, 'label': 'Node 5', 'color': {'background': 'purple', 'border': 'black'}}
    ]
    edges = [
        {'from': 1, 'to': 2},
        {'from': 1, 'to': 3},
        {'from': 2, 'to': 4},
        {'from': 2, 'to': 5}
    ]'''

    logging.info("Will return the graph data in JSON format to the react frontend.")
    logging.info("")
    logging.info("")
    return jsonify(convert2visNetworkFormat(graph_data))

def main():
     pass

if __name__ == "__main__":
    # Load data from JSON files
    main()

