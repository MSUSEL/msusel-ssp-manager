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
debugging = False

def listTechniquesForEachStage(tacticsAndTechniquesGraph, tacticsOriginalIDsList):
    attackPathGraph = [] # This is a list of lists, where each list contains the techniques for a given tactic

    if debugging:
        logging.info("Enterred listTechniquesForEachStage method.")
        logging.info(f"tacticsOriginalIDsList: {tacticsOriginalIDsList}")
        logging.info("Will create a networkx directed graph for the attack paths and store it in a local variable called attackPathsGraph.")
        #List the edges in the tacticsOnlyGraph: [('tactic/tactic_00003', 'tactic/tactic_00005')]
        logging.info(f"Type of the tacticsAndTechniquesGraph: {type(tacticsAndTechniquesGraph)}")
        logging.info(f"List the nodes in the tacticsAndTechniquesGraph: {tacticsAndTechniquesGraph.nodes}")
        logging.info(f"List the edges in the tacticsAndTechniquesGraph: {tacticsAndTechniquesGraph.edges}")

    for tactic in tacticsOriginalIDsList:
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
            attackPathGraph.append(techniques)
            
            # Print or process the tactic and its directly connected techniques
            #print(f"Tactic: {tactic}, Directly Connected Techniques: {techniques}")
    if debugging:
        logging.info(f"Attack path graph: {attackPathGraph}")
    return attackPathGraph # This is a list of lists, where each list contains the techniques for a given tactic


def createNetworkXGraph(listOfList):
    attackPathGraph = nx.DiGraph()
    attackPathGraph.add_node("Start")
    attackPathGraph.add_node("End")

    # Connect "Start" to the first list of techniques
    for technique in listOfList[0]:
        attackPathGraph.add_edge("Start", technique)

    # Connect each technique to the techniques in the next list
    for i in range(len(listOfList) - 1):
        for technique1 in listOfList[i]:
            for technique2 in listOfList[i + 1]:
                attackPathGraph.add_edge(technique1, technique2)

    # Connect the techniques in the last list to "End"
    for technique in listOfList[-1]:
        attackPathGraph.add_edge(technique, "End")

    return attackPathGraph


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
            nodes.append({'id': node_id, 'label': node['label'], 'color': {'background': '#FF0000', 'border': 'black'}})
        else:
            nodes.append({'id': node_id, 'label': node['label'], 'color': {'background': '#CCE5FF', 'border': 'black'}})
        node_id += 1
    for edge in initial['edges']:
        edges.append({'from': node_map[edge['from']], 'to': node_map[edge['to']]})
    return {'nodes': nodes, 'edges': edges}


@attack_blueprint.route('/attack_paths', methods=['GET','POST'])
def attacks():
    # Current working directory or project root
    cur_dir = os.getcwd()
    
    # Initialize components
    db_connection = DatabaseConnection()
    query_service = DatabaseQueryService(db_connection)
    data_manager = ManageData(cur_dir, query_service)

    listOfLists = listTechniquesForEachStage(data_manager.tacticsAndTechniquesGraph, data_manager.tacticsOriginalIDsList)
    attack_paths_graph = createNetworkXGraph(listOfLists)


    
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

    return jsonify(convert2visNetworkFormat(graph_data))

def main():
     pass

if __name__ == "__main__":
    # Load data from JSON files
    main()