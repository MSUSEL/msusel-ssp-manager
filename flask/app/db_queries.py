# Important: cursors can only be iterated on once. 
# If you want to iterate on the cursor multiple times, you need to store the results in a list.
from flask import jsonify
import json
import os
import logging
from arango.client import ArangoClient
from typing import List, Dict, Any

logging.basicConfig(level=logging.INFO)
debugging = False

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
            return self.db.aql.execute(query, bind_vars=bind_vars, ttl=300, count=True) 
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

    def fetch_tactic_id(self, tacticsOriginalIDsList: list) -> Any:
        """
        Fetch tactic IDs for the given list of original IDs.
        """
        tactic_id_query = '''
            FOR tac IN tactic
                FILTER tac.original_id IN @tacticsOriginalIDsList
                RETURN tac._id
        '''
        bind_vars = {'tacticsOriginalIDsList': tacticsOriginalIDsList}
        return self.db_connection.execute_aql(tactic_id_query, bind_vars)

    
    def fetch_technique_id(self, tacticID: Any) -> Any:
        """
        Fetch technique IDs for the given tactic ID.
        """
        technique_id_query = '''
            FOR tac_tech in TacticTechnique 
                FILTER tac_tech._from == @tacticID 
                RETURN distinct tac_tech._to
        '''
        bind_vars = {'tacticID': tacticID}
        return self.db_connection.execute_aql(technique_id_query, bind_vars)
    

    def fetch_tactic_name(self, tacticID: Any) -> Any:
        """
        Fetch tactic name for the given tactic ID.
        """
        tactic_name_query = '''
            FOR tac in tactic 
                FILTER tac._id == @tacticID 
                RETURN tac.name
        '''
        bind_vars = {'tacticID': tacticID}
        return self.db_connection.execute_aql(tactic_name_query, bind_vars)
    
    def fetch_original_tacticID(self, tacticID: Any) -> Any:
        """
        Fetch tactic name for the given tactic ID.
        """
        tactic_originalID_query = '''
            FOR tac in tactic 
                FILTER tac._id == @tacticID 
                RETURN tac.original_id
        '''
        bind_vars = {'tacticID': tacticID}
        return self.db_connection.execute_aql(tactic_originalID_query, bind_vars)


    def fetch_attacks_against_cwes(self, findings_list: List[str]) -> Any:
        if debugging:
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
        logging.info("Entered print_cursor method.")
        logging.info(f"Cursor length: {cursor.count()}")
        logging.info(f"Cursor has more: {cursor.has_more()}")
        for doc in cursor:
            logging.info(doc)
        logging.info("Exited print_cursor method.")


    def get_techniques(self, cursor: Any):
        techniques = [doc for doc in cursor]  # Convert cursor to list of dictionaries
        json_techniques = json.dumps(techniques)
        return json.loads(json_techniques)
