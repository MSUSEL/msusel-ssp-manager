# Important: cursors can only be iterated on once. 
# If you want to iterate on the cursor multiple times, you need to store the results in a list.
from flask import Blueprint, jsonify
import os
import logging
from .db_queries import DatabaseConnection, DatabaseQueryService
from .priority_controls import ManageData
import networkx as nx


logging.basicConfig(level=logging.INFO)
debugging = False

tactics_blueprint = Blueprint('tactics', __name__)


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



@tactics_blueprint.route('/graph_data', methods=['GET','POST'])
def tactics():
    # Current working directory or project root
    cur_dir = os.getcwd()
    
    # Initialize components
    db_connection = DatabaseConnection()
    query_service = DatabaseQueryService(db_connection)
    data_manager = ManageData(cur_dir, query_service)
    
    # Combine nodes and edges into a single object
    graph_data = convert_nx_to_vis_format(data_manager.tacticsAndTechniquesGraph)

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
    main()