from arango import ArangoClient
import json, get_json_from_db, insert_control_data, insert_tech_ctrl_edge, insert_tactic_path
import rm_dup_tac_tech
import os
import logging

# set up logging
logging.basicConfig(level=logging.INFO)

# access to the arango database
arango_url = os.getenv('ARANGO_DB_URL', 'http://brondb:8529')
arango_db_name = os.getenv('ARANGO_DB_NAME', 'BRON')
arango_username = os.getenv('ARANGO_DB_USERNAME', 'root')
arango_password = os.getenv('ARANGO_DB_PASSWORD', 'changeme')
client = ArangoClient(hosts=arango_url)
logging.info(f"Connecting to ArangoDB at {arango_url} with username {arango_username} and password {arango_password}")
db = client.db(arango_db_name, username=arango_username, password=arango_password)
logging.info(f"Connected to ArangoDB database {arango_db_name}")
        

#client = ArangoClient()
#db = client.db('BRON', username = 'root', password = 'changeme')

# open the json file
with open("nist800-53-r5-mappings2.json", 'r') as file:
    data = json.load(file)

    # execute functions in other src files
    print("Inserting TechniqueCapac Edge Collection...")
    get_json_from_db.get_tech_capac(db)
    print("Inserting Control Collection...")
    insert_control_data.insert(db, data)
    print("Inserting TechniqueControl Edge Collection...")
    insert_tech_ctrl_edge.create_edge(db, data)
    print("Inserting TacticTactic Collection...")
    insert_tactic_path.create_edge(db)
    print("Removing Duplicates in TacticTechnique Edge Collection...")
    rm_dup_tac_tech.remove_duplicates(db)
    print("Done")
