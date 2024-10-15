# This program turns this:

initial = {'nodes': [{'id': 'tactic/TA0006', 'label': 'tactic/TA0006'}, {'id': 'technique/T1040', 'label': 'technique/T1040'}, {'id': 'tactic/TA0007', 'label': 'tactic/TA0007'}, {'id': 'tactic/TA0009', 'label': 'tactic/TA0009'}, {'id': 'technique/T1056.004', 'label': 'technique/T1056.004'}, {'id': 'tactic/TA0040', 'label': 'tactic/TA0040'}, {'id': 'technique/T1499', 'label': 'technique/T1499'}, {'id': 'tactic/tactic_00003', 'label': 'tactic/tactic_00003'}, {'id': 'tactic/tactic_00005', 'label': 'tactic/tactic_00005'}], 'edges': [{'from': 'tactic/TA0006', 'to': 'technique/T1040'}, {'from': 'tactic/TA0006', 'to': 'technique/T1056.004'}, {'from': 'technique/T1040', 'to': 'tactic/TA0007'}, {'from': 'tactic/TA0009', 'to': 'technique/T1056.004'}, {'from': 'tactic/TA0040', 'to': 'technique/T1499'}, {'from': 'tactic/tactic_00003', 'to': 'tactic/tactic_00005'}]}

# Into this:
# Example graph data
nodes = [
    {'id': 1, 'label': 'Node 1'},
    {'id': 2, 'label': 'Node 2'},
    {'id': 3, 'label': 'Node 3'},
    {'id': 4, 'label': 'Node 4'},
    {'id': 5, 'label': 'Node 5'}
]

edges = [
    {'from': 1, 'to': 2},
    {'from': 1, 'to': 3},
    {'from': 2, 'to': 4},
    {'from': 2, 'to': 5}
]

# This is the code that does the conversion
def convert(initial):
    nodes = []
    edges = []
    node_id = 1
    node_map = {}
    for node in initial['nodes']:
        node_map[node['id']] = node_id
        nodes.append({'id': node_id, 'label': node['label']})
        node_id += 1
    for edge in initial['edges']:
        edges.append({'from': node_map[edge['from']], 'to': node_map[edge['to']]})
    return {'nodes': nodes, 'edges': edges}

# This is the output of the conversion
print(convert(initial))