# This script creates TacticTactic edge collection

def create_edge(db):

    # constant indicates a name of edge collection will be create
    TAC_TAC = 'TacticTactic'

    # gets the graph data from the database
    graph = db.graph('BRONGraph')

    # delete edge in the graph and edge collection if they exist
    if graph.has_edge_definition(TAC_TAC):
        graph.delete_edge_definition(TAC_TAC)
    if db.has_collection(TAC_TAC):
        db.delete_collection(TAC_TAC)

    # creates an edge in the graph
    graph.create_edge_definition(
        edge_collection = TAC_TAC,
        from_vertex_collections = ['tactic'],
        to_vertex_collections = ['tactic']
    )

    # creates an edge collection
    tt = graph.edge_collection(TAC_TAC)
    insert_paths(tt)



# # gets data from the collection
# tactic = db.collection('tactic')

def insert_paths(tt):
    # specified the tactics
    temp = 'tactic/TA00'
    collection = temp + '09'
    command_ctrl = temp + '11'
    credential_access = temp + '06'
    defense_evasion = temp + '05'
    discovery = temp + '07'
    execution = temp + '02'
    exfiltration = temp + '10'
    impact = temp + '40'
    init_access = temp + '01'
    lateral_movement = temp + '08'
    persistence = temp + '03'
    priv_escalation = temp + '04'
    reconnaissance = temp + '43'
    rsrc_dev = temp + '42'


    # creat paths between tactics
    tac1 = {'_to' : rsrc_dev, '_from': reconnaissance}
    tac2 = {'_to' : init_access, '_from': rsrc_dev}
    tac3 = {'_to' : execution, '_from': init_access}
    tac4 = {'_to' : persistence, '_from': execution}
    tac5 = {'_to' : priv_escalation, '_from': persistence}
    tac6 = {'_to' : defense_evasion, '_from': priv_escalation}
    tac7 = {'_to' : credential_access, '_from': defense_evasion}
    tac8 = {'_to' : discovery, '_from': credential_access}
    tac9 = {'_to' : lateral_movement, '_from': discovery}
    tac10 = {'_to' : collection, '_from': lateral_movement}
    tac11 = {'_to' : command_ctrl, '_from': collection}
    tac12 = {'_to' : exfiltration, '_from': command_ctrl}
    tac13 = {'_to' : impact, '_from': exfiltration}

    # inserts the data to the edge collection
    tt.import_bulk([tac1, tac2, tac3, tac4, tac5, tac6, tac7, tac8, tac9, tac10, tac11, tac12, tac13])
