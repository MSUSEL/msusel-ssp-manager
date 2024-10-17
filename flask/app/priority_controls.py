# Important: cursors can only be iterated on once. 
# If you want to iterate on the cursor multiple times, you need to store the results in a list.
from flask import Blueprint, request, current_app as app, send_from_directory, jsonify, send_file, make_response
import os
import json
import logging
from typing import List, Dict, Tuple, Any
import ast
from .db_queries import DatabaseConnection, DatabaseQueryService
from .manageData import ManageData
import networkx as nx
from pyvis import network as net
import traceback

logging.basicConfig(level=logging.INFO)
debugging = False

priority_blueprint = Blueprint('priority', __name__)


@priority_blueprint.route('/table_data', methods=['GET','POST'])
def priority():
    # Current working directory or project root
    cur_dir = os.getcwd()
    
    # Initialize components
    db_connection = DatabaseConnection()
    query_service = DatabaseQueryService(db_connection)
    data_manager = ManageData(cur_dir, query_service)

    return data_manager.json_priority_controls_table_data


def main():
    pass

if __name__ == "__main__":
    main()