'''import networkx as nx

# Assuming you already have tacticsOnlyGraph and tacticsAndTechniquesGraph created
# Here's a simple structure for these graphs based on your provided data

# Sample tactic-only graph (Directed)
tacticsOnlyGraph = nx.DiGraph()
tacticsOnlyGraph.add_edges_from([('tactic/tactic_00013', 'tactic/tactic_00014'), ('tactic/tactic_00014', 'tactic/tactic_00009'), ('tactic/tactic_00009', 'tactic/tactic_00006'), ('tactic/tactic_00006', 'tactic/tactic_00011'), ('tactic/tactic_00011', 'tactic/tactic_00012'), ('tactic/tactic_00012', 'tactic/tactic_00004'), ('tactic/tactic_00004', 'tactic/tactic_00003'), ('tactic/tactic_00003', 'tactic/tactic_00005'), ('tactic/tactic_00005', 'tactic/tactic_00010'), ('tactic/tactic_00010', 'tactic/tactic_00001'), ('tactic/tactic_00001', 'tactic/tactic_00002')])

# Assuming tacticsOnlyGraph.nodes is an iterable (e.g., dict_keys or similar)
listOfTactics = list(tacticsOnlyGraph.nodes)

print(listOfTactics)


# Sample tactics and techniques graph (Undirected)
tacticsAndTechniquesGraph = nx.Graph()
tacticsAndTechniquesGraph.add_edges_from([('tactic/TA0011', 'technique/T1001.002'), ('tactic/TA0011', 'technique/T1090.001'), ('tactic/TA0011', 'technique/T1090.004'), ('tactic/TA0006', 'technique/T1003'), ('tactic/TA0006', 'technique/T1040'), ('tactic/TA0006', 'technique/T1056'), ('tactic/TA0006', 'technique/T1056.004'), ('tactic/TA0006', 'technique/T1110'), ('tactic/TA0006', 'technique/T1110.001'), ('tactic/TA0006', 'technique/T1110.002'), ('tactic/TA0006', 'technique/T1110.003'), ('tactic/TA0006', 'technique/T1110.004'), ('tactic/TA0006', 'technique/T1111'), ('tactic/TA0006', 'technique/T1528'), ('tactic/TA0006', 'technique/T1539'), ('tactic/TA0006', 'technique/T1552.001'), ('tactic/TA0006', 'technique/T1552.002'), ('tactic/TA0006', 'technique/T1552.003'), ('tactic/TA0006', 'technique/T1552.004'), ('tactic/TA0006', 'technique/T1552.006'), ('tactic/TA0006', 'technique/T1555'), ('tactic/TA0006', 'technique/T1556'), ('tactic/TA0006', 'technique/T1556.006'), ('tactic/TA0006', 'technique/T1557'), ('tactic/TA0006', 'technique/T1557.002'), ('tactic/TA0006', 'technique/T1557.003'), ('tactic/TA0006', 'technique/T1558'), ('tactic/TA0006', 'technique/T1558.003'), ('tactic/TA0006', 'technique/T1606'), ('tactic/TA0006', 'technique/T1606.001'), ('tactic/TA0009', 'technique/T1005'), ('tactic/TA0009', 'technique/T1039'), ('tactic/TA0009', 'technique/T1056'), ('tactic/TA0009', 'technique/T1056.004'), ('tactic/TA0009', 'technique/T1113'), ('tactic/TA0009', 'technique/T1114.002'), ('tactic/TA0009', 'technique/T1115'), ('tactic/TA0009', 'technique/T1119'), ('tactic/TA0009', 'technique/T1123'), ('tactic/TA0009', 'technique/T1125'), ('tactic/TA0009', 'technique/T1185'), ('tactic/TA0009', 'technique/T1213'), ('tactic/TA0009', 'technique/T1530'), ('tactic/TA0009', 'technique/T1557'), ('tactic/TA0009', 'technique/T1557.002'), ('tactic/TA0009', 'technique/T1557.003'), ('tactic/TA0009', 'technique/T1602'), ('tactic/TA0007', 'technique/T1007'), ('tactic/TA0007', 'technique/T1012'), ('tactic/TA0007', 'technique/T1016'), ('tactic/TA0007', 'technique/T1018'), ('tactic/TA0007', 'technique/T1033'), ('tactic/TA0007', 'technique/T1040'), ('tactic/TA0007', 'technique/T1046'), ('tactic/TA0007', 'technique/T1049'), ('tactic/TA0007', 'technique/T1057'), ('tactic/TA0007', 'technique/T1069'), ('tactic/TA0007', 'technique/T1082'), ('tactic/TA0007', 'technique/T1083'), ('tactic/TA0007', 'technique/T1087'), ('tactic/TA0007', 'technique/T1120'), ('tactic/TA0007', 'technique/T1124'), ('tactic/TA0007', 'technique/T1135'), ('tactic/TA0007', 'technique/T1217'), ('tactic/TA0007', 'technique/T1614'), ('tactic/TA0007', 'technique/T1615'), ('tactic/TA0005', 'technique/T1014'), ('tactic/TA0005', 'technique/T1027'), ('tactic/TA0005', 'technique/T1027.003'), ('tactic/TA0005', 'technique/T1027.004'), ('tactic/TA0005', 'technique/T1027.006'), ('tactic/TA0005', 'technique/T1027.009'), ('tactic/TA0005', 'technique/T1036'), ('tactic/TA0005', 'technique/T1036.001'), ('tactic/TA0005', 'technique/T1036.004'), ('tactic/TA0005', 'technique/T1036.005'), ('tactic/TA0005', 'technique/T1036.006'), ('tactic/TA0005', 'technique/T1036.007'), ('tactic/TA0005', 'technique/T1055'), ('tactic/TA0005', 'technique/T1055.003'), ('tactic/TA0005', 'technique/T1070'), ('tactic/TA0005', 'technique/T1078'), ('tactic/TA0005', 'technique/T1078.001'), ('tactic/TA0005', 'technique/T1112'), ('tactic/TA0005', 'technique/T1134'), ('tactic/TA0005', 'technique/T1134.001'), ('tactic/TA0005', 'technique/T1134.002'), ('tactic/TA0005', 'technique/T1134.003'), ('tactic/TA0005', 'technique/T1211'), ('tactic/TA0005', 'technique/T1218.001'), ('tactic/TA0005', 'technique/T1221'), ('tactic/TA0005', 'technique/T1542.002'), ('tactic/TA0005', 'technique/T1542.003'), ('tactic/TA0005', 'technique/T1548'), ('tactic/TA0005', 'technique/T1548.004'), ('tactic/TA0005', 'technique/T1550.001'), ('tactic/TA0005', 'technique/T1550.002'), ('tactic/TA0005', 'technique/T1550.003'), ('tactic/TA0005', 'technique/T1550.004'), ('tactic/TA0005', 'technique/T1553.002'), ('tactic/TA0005', 'technique/T1553.004'), ('tactic/TA0005', 'technique/T1556'), ('tactic/TA0005', 'technique/T1556.006'), ('tactic/TA0005', 'technique/T1562.001'), ('tactic/TA0005', 'technique/T1562.002'), ('tactic/TA0005', 'technique/T1562.003'), ('tactic/TA0005', 'technique/T1562.004'), ('tactic/TA0005', 'technique/T1562.007'), ('tactic/TA0005', 'technique/T1562.008'), ('tactic/TA0005', 'technique/T1562.009'), ('tactic/TA0005', 'technique/T1564.009'), ('tactic/TA0005', 'technique/T1574.001'), ('tactic/TA0005', 'technique/T1574.002'), ('tactic/TA0005', 'technique/T1574.004'), ('tactic/TA0005', 'technique/T1574.005'), ('tactic/TA0005', 'technique/T1574.006'), ('tactic/TA0005', 'technique/T1574.007'), ('tactic/TA0005', 'technique/T1574.008'), ('tactic/TA0005', 'technique/T1574.009'), ('tactic/TA0005', 'technique/T1574.010'), ('tactic/TA0005', 'technique/T1574.011'), ('tactic/TA0005', 'technique/T1574.013'), ('tactic/TA0005', 'technique/T1600'), ('tactic/TA0005', 'technique/T1620'), ('tactic/TA0005', 'technique/T1647'), ('tactic/TA0008', 'technique/T1021'), ('tactic/TA0008', 'technique/T1021.002'), ('tactic/TA0008', 'technique/T1072'), ('tactic/TA0008', 'technique/T1080'), ('tactic/TA0008', 'technique/T1534'), ('tactic/TA0008', 'technique/T1550.001'), ('tactic/TA0008', 'technique/T1550.002'), ('tactic/TA0008', 'technique/T1550.003'), ('tactic/TA0008', 'technique/T1550.004'), ('tactic/TA0008', 'technique/T1563'), ('tactic/TA0003', 'technique/T1037'), ('tactic/TA0003', 'technique/T1078'), ('tactic/TA0003', 'technique/T1078.001'), ('tactic/TA0003', 'technique/T1133'), ('tactic/TA0003', 'technique/T1176'), ('tactic/TA0003', 'technique/T1505.003'), ('tactic/TA0003', 'technique/T1505.004'), ('tactic/TA0003', 'technique/T1505.005'), ('tactic/TA0003', 'technique/T1542.002'), ('tactic/TA0003', 'technique/T1542.003'), ('tactic/TA0003', 'technique/T1543'), ('tactic/TA0003', 'technique/T1543.001'), ('tactic/TA0003', 'technique/T1543.003'), ('tactic/TA0003', 'technique/T1543.004'), ('tactic/TA0003', 'technique/T1546.001'), ('tactic/TA0003', 'technique/T1546.004'), ('tactic/TA0003', 'technique/T1546.008'), ('tactic/TA0003', 'technique/T1546.016'), ('tactic/TA0003', 'technique/T1547'), ('tactic/TA0003', 'technique/T1547.001'), ('tactic/TA0003', 'technique/T1547.004'), ('tactic/TA0003', 'technique/T1547.006'), ('tactic/TA0003', 'technique/T1547.009'), ('tactic/TA0003', 'technique/T1547.014'), ('tactic/TA0003', 'technique/T1554'), ('tactic/TA0003', 'technique/T1556'), ('tactic/TA0003', 'technique/T1556.006'), ('tactic/TA0003', 'technique/T1574.001'), ('tactic/TA0003', 'technique/T1574.002'), ('tactic/TA0003', 'technique/T1574.004'), ('tactic/TA0003', 'technique/T1574.005'), ('tactic/TA0003', 'technique/T1574.006'), ('tactic/TA0003', 'technique/T1574.007'), ('tactic/TA0003', 'technique/T1574.008'), ('tactic/TA0003', 'technique/T1574.009'), ('tactic/TA0003', 'technique/T1574.010'), ('tactic/TA0003', 'technique/T1574.011'), ('tactic/TA0003', 'technique/T1574.013'), ('technique/T1037', 'tactic/TA0004'), ('tactic/TA0004', 'technique/T1055'), ('tactic/TA0004', 'technique/T1055.003'), ('tactic/TA0004', 'technique/T1078'), ('tactic/TA0004', 'technique/T1078.001'), ('tactic/TA0004', 'technique/T1134'), ('tactic/TA0004', 'technique/T1134.001'), ('tactic/TA0004', 'technique/T1134.002'), ('tactic/TA0004', 'technique/T1134.003'), ('tactic/TA0004', 'technique/T1543'), ('tactic/TA0004', 'technique/T1543.001'), ('tactic/TA0004', 'technique/T1543.003'), ('tactic/TA0004', 'technique/T1543.004'), ('tactic/TA0004', 'technique/T1546.001'), ('tactic/TA0004', 'technique/T1546.004'), ('tactic/TA0004', 'technique/T1546.008'), ('tactic/TA0004', 'technique/T1546.016'), ('tactic/TA0004', 'technique/T1547'), ('tactic/TA0004', 'technique/T1547.001'), ('tactic/TA0004', 'technique/T1547.004'), ('tactic/TA0004', 'technique/T1547.006'), ('tactic/TA0004', 'technique/T1547.009'), ('tactic/TA0004', 'technique/T1547.014'), ('tactic/TA0004', 'technique/T1548'), ('tactic/TA0004', 'technique/T1548.004'), ('tactic/TA0004', 'technique/T1574.001'), ('tactic/TA0004', 'technique/T1574.002'), ('tactic/TA0004', 'technique/T1574.004'), ('tactic/TA0004', 'technique/T1574.005'), ('tactic/TA0004', 'technique/T1574.006'), ('tactic/TA0004', 'technique/T1574.007'), ('tactic/TA0004', 'technique/T1574.008'), ('tactic/TA0004', 'technique/T1574.009'), ('tactic/TA0004', 'technique/T1574.010'), ('tactic/TA0004', 'technique/T1574.011'), ('tactic/TA0004', 'technique/T1574.013'), ('tactic/TA0004', 'technique/T1611'), ('tactic/TA0002', 'technique/T1072'), ('technique/T1078', 'tactic/TA0001'), ('tactic/TA0001', 'technique/T1078.001'), ('tactic/TA0001', 'technique/T1133'), ('tactic/TA0001', 'technique/T1195.001'), ('tactic/TA0001', 'technique/T1195.002'), ('tactic/TA0001', 'technique/T1566'), ('tactic/TA0001', 'technique/T1566.001'), ('tactic/TA0001', 'technique/T1566.002'), ('tactic/TA0001', 'technique/T1566.003'), ('tactic/TA0040', 'technique/T1491'), ('tactic/TA0040', 'technique/T1498.001'), ('tactic/TA0040', 'technique/T1498.002'), ('tactic/TA0040', 'technique/T1499'), ('tactic/TA0040', 'technique/T1499.001'), ('tactic/TA0040', 'technique/T1499.002'), ('tactic/TA0040', 'technique/T1499.003'), ('tactic/TA0040', 'technique/T1499.004'), ('tactic/TA0040', 'technique/T1531'), ('tactic/TA0040', 'technique/T1565.002'), ('tactic/TA0042', 'technique/T1584.002'), ('tactic/TA0043', 'technique/T1590'), ('tactic/TA0043', 'technique/T1592'), ('tactic/TA0043', 'technique/T1592.002'), ('tactic/TA0043', 'technique/T1595'), ('tactic/TA0043', 'technique/T1598'), ('tactic/TA0043', 'technique/T1598.001'), ('tactic/TA0043', 'technique/T1598.002'), ('tactic/TA0043', 'technique/T1598.003'), ('tactic/tactic_00013', 'tactic/tactic_00014'), ('tactic/tactic_00014', 'tactic/tactic_00009'), ('tactic/tactic_00009', 'tactic/tactic_00006'), ('tactic/tactic_00006', 'tactic/tactic_00011'), ('tactic/tactic_00011', 'tactic/tactic_00012'), ('tactic/tactic_00012', 'tactic/tactic_00004'), ('tactic/tactic_00004', 'tactic/tactic_00003'), ('tactic/tactic_00003', 'tactic/tactic_00005'), ('tactic/tactic_00005', 'tactic/tactic_00010'), ('tactic/tactic_00010', 'tactic/tactic_00001'), ('tactic/tactic_00001', 'tactic/tactic_00002')])

# Iterate through all edges in the tacticsAndTechniquesGraph
for edge in tacticsAndTechniquesGraph.edges:
    node1, node2 = edge
    
    # Check if one node is a tactic and the other is a technique
    if (node1.startswith('tactic/') and node2.startswith('technique/')) or (node1.startswith('technique/') and node2.startswith('tactic/')):
        # Print the edge (tactic, technique)
        print(f"Edge between Tactic and Technique: {node1} -> {node2}")

tacticsOriginalIDsList = ['TA0043', 'TA0042', 'TA0001', 'TA0002', 'TA0003', 'TA0004', 'TA0005', 'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0011']
# Iterate through each tactic in the tacticsOnlyGraph
for tactic in tacticsOriginalIDsList:
    # Check if the tactic exists in the tacticsAndTechniquesGraph
    if tacticsAndTechniquesGraph.has_node(tactic):
        # Get direct neighbors (connected nodes) in the tacticsAndTechniquesGraph
        connected_nodes = tacticsAndTechniquesGraph.neighbors(tactic)
        
        # Filter neighbors to get only techniques (nodes starting with "technique/")
        techniques = [node for node in connected_nodes if node.startswith('technique/')]
        
        # Print or process the tactic and its directly connected techniques
        print(f"Tactic: {tactic}, Directly Connected Techniques: {techniques}")'''






listOfList = [['technique/T1001.002', 'technique/T1090.001', 'technique/T1090.004'], ['technique/T1584.002'], ['technique/T1491', 'technique/T1498.001', 'technique/T1498.002', 'technique/T1499', 'technique/T1499.001', 'technique/T1499.002', 'technique/T1499.003', 'technique/T1499.004', 'technique/T1531', 'technique/T1565.002'], ['technique/T1021', 'technique/T1021.002', 'technique/T1072', 'technique/T1080', 'technique/T1534', 'technique/T1550.001', 'technique/T1550.002', 'technique/T1550.003', 'technique/T1550.004', 'technique/T1563'], ['technique/T1003', 'technique/T1040', 'technique/T1056', 'technique/T1056.004', 'technique/T1110', 'technique/T1110.001', 'technique/T1110.002', 'technique/T1110.003', 'technique/T1110.004', 'technique/T1111', 'technique/T1528', 'technique/T1539', 'technique/T1552.001', 'technique/T1552.002', 'technique/T1552.003', 'technique/T1552.004', 'technique/T1552.006', 'technique/T1555', 'technique/T1556', 'technique/T1556.006', 'technique/T1557', 'technique/T1557.002', 'technique/T1557.003', 'technique/T1558', 'technique/T1558.003', 'technique/T1606', 'technique/T1606.001'], ['technique/T1005', 'technique/T1039', 'technique/T1056', 'technique/T1056.004', 'technique/T1113', 'technique/T1114.002', 'technique/T1115', 'technique/T1119', 'technique/T1123', 'technique/T1125', 'technique/T1185', 'technique/T1213', 'technique/T1530', 'technique/T1557', 'technique/T1557.002', 'technique/T1557.003', 'technique/T1602'], ['technique/T1590', 'technique/T1592', 'technique/T1592.002', 'technique/T1595', 'technique/T1598', 'technique/T1598.001', 'technique/T1598.002', 'technique/T1598.003'], ['technique/T1014', 'technique/T1027', 'technique/T1027.003', 'technique/T1027.004', 'technique/T1027.006', 'technique/T1027.009', 'technique/T1036', 'technique/T1036.001', 'technique/T1036.004', 'technique/T1036.005', 'technique/T1036.006', 'technique/T1036.007', 'technique/T1055', 'technique/T1055.003', 'technique/T1070', 'technique/T1078', 'technique/T1078.001', 'technique/T1112', 'technique/T1134', 'technique/T1134.001', 'technique/T1134.002', 'technique/T1134.003', 'technique/T1211', 'technique/T1218.001', 'technique/T1221', 'technique/T1542.002', 'technique/T1542.003', 'technique/T1548', 'technique/T1548.004', 'technique/T1550.001', 'technique/T1550.002', 'technique/T1550.003', 'technique/T1550.004', 'technique/T1553.002', 'technique/T1553.004', 'technique/T1556', 'technique/T1556.006', 'technique/T1562.001', 'technique/T1562.002', 'technique/T1562.003', 'technique/T1562.004', 'technique/T1562.007', 'technique/T1562.008', 'technique/T1562.009', 'technique/T1564.009', 'technique/T1574.001', 'technique/T1574.002', 'technique/T1574.004', 'technique/T1574.005', 'technique/T1574.006', 'technique/T1574.007', 'technique/T1574.008', 'technique/T1574.009', 'technique/T1574.010', 'technique/T1574.011', 'technique/T1574.013', 'technique/T1600', 'technique/T1620', 'technique/T1647'], ['technique/T1072'], ['technique/T1078', 'technique/T1078.001', 'technique/T1133', 'technique/T1195.001', 'technique/T1195.002', 'technique/T1566', 'technique/T1566.001', 'technique/T1566.002', 'technique/T1566.003'], ['technique/T1007', 'technique/T1012', 'technique/T1016', 'technique/T1018', 'technique/T1033', 'technique/T1040', 'technique/T1046', 'technique/T1049', 'technique/T1057', 'technique/T1069', 'technique/T1082', 'technique/T1083', 'technique/T1087', 'technique/T1120', 'technique/T1124', 'technique/T1135', 'technique/T1217', 'technique/T1614', 'technique/T1615'], ['technique/T1037', 'technique/T1055', 'technique/T1055.003', 'technique/T1078', 'technique/T1078.001', 'technique/T1134', 'technique/T1134.001', 'technique/T1134.002', 'technique/T1134.003', 'technique/T1543', 'technique/T1543.001', 'technique/T1543.003', 'technique/T1543.004', 'technique/T1546.001', 'technique/T1546.004', 'technique/T1546.008', 'technique/T1546.016', 'technique/T1547', 'technique/T1547.001', 'technique/T1547.004', 'technique/T1547.006', 'technique/T1547.009', 'technique/T1547.014', 'technique/T1548', 'technique/T1548.004', 'technique/T1574.001', 'technique/T1574.002', 'technique/T1574.004', 'technique/T1574.005', 'technique/T1574.006', 'technique/T1574.007', 'technique/T1574.008', 'technique/T1574.009', 'technique/T1574.010', 'technique/T1574.011', 'technique/T1574.013', 'technique/T1611'], ['technique/T1037', 'technique/T1078', 'technique/T1078.001', 'technique/T1133', 'technique/T1176', 'technique/T1505.003', 'technique/T1505.004', 'technique/T1505.005', 'technique/T1542.002', 'technique/T1542.003', 'technique/T1543', 'technique/T1543.001', 'technique/T1543.003', 'technique/T1543.004', 'technique/T1546.001', 'technique/T1546.004', 'technique/T1546.008', 'technique/T1546.016', 'technique/T1547', 'technique/T1547.001', 'technique/T1547.004', 'technique/T1547.006', 'technique/T1547.009', 'technique/T1547.014', 'technique/T1554', 'technique/T1556', 'technique/T1556.006', 'technique/T1574.001', 'technique/T1574.002', 'technique/T1574.004', 'technique/T1574.005', 'technique/T1574.006', 'technique/T1574.007', 'technique/T1574.008', 'technique/T1574.009', 'technique/T1574.010', 'technique/T1574.011', 'technique/T1574.013']]


# We have a list of lists.
# We will create a networkx graph.
# We will fisrt insert a single node that we will call "Start" and connect it to the first list of techniques.
# Then each technique in the first list will be connected to the techniques in the second list.
# We will repeat this process until we reach the last list of techniques.
# Finally, we will connect each technique in the last list to a single node that we will call "End".
import networkx as nx

def create_graph_with_lists(lists, start_node, end_node):
    # Initialize the directed graph
    G = nx.DiGraph()
    
    # Add the start node
    G.add_node(start_node)
    
    # Connect start node to each element of the first list
    for element in lists[0]:
        G.add_edge(start_node, element)
    
    # Loop through the lists to connect elements from one list to the next
    for i in range(len(lists) - 1):
        for elem1 in lists[i]:
            for elem2 in lists[i + 1]:
                G.add_edge(elem1, elem2)
    
    # Connect elements of the last list to the end node
    for element in lists[-1]:
        G.add_edge(element, end_node)
    
    # Add the end node to the graph
    G.add_node(end_node)
    
    return G

# Example usage
lists_of_elements = [
    ['A1', 'A2', 'A3'],
    ['B1', 'B2'],
    ['C1', 'C2', 'C3', 'C4']
]
start = "Start"
end = "End"

graph = create_graph_with_lists(lists_of_elements, start, end)

# Output the edges to see the structure
print(list(graph.edges()))



