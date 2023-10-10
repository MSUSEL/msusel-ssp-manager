# imports
import networkx as nx
from pyvis import network as net
import webbrowser
import os
import json
import json2table


# method to create web browser graph
def make_graph(db, cursor_tac_tec, data_list, user_tac):
    #temp
    print('Creating a graph...')

    # setting up the graph
    tac_tac = db.collection('TacticTactic')
    graph = nx.Graph()
    g1 = net.Network(height='100vh', width='100%', notebook=True, bgcolor=212121, font_color="white")
    g2 = net.Network(height='100vh', width='100%', notebook=True, bgcolor=212121, font_color="white")

    # graph that contains only the paths between tactics
    tac_graph = nx.DiGraph()

    # list for easy checking later; contains ._from value in TacticTechnique
    tactech_from_list = []

    # takes the ._from ._to edge from the cursor query
    for item in cursor_tac_tec:
        tac, tech = item.items()
        # adding nodes and edge into networkx graph
        graph.add_nodes_from([tac[1], tech[1]])
        graph.add_edge(tac[1], tech[1])
        # adding tactic into list for easy checking
        tactech_from_list.append(tac[1])


    # this is checking the BRON database for tactic to tactic 
    # paths that need to be placed into the networkx graph
    for tt in tac_tac:
        if tt['_from'] in tactech_from_list and tt['_to'] in tactech_from_list:
            graph.add_edge(tt['_from'], tt['_to'])
            tac_graph.add_edge(tt['_from'], tt['_to'])

    # checks whether the tactic specified by the user is in the graph
    user_pri = None
    if user_tac in tactech_from_list:
        user_pri = user_tac

    prioritize_lists = show_prioritize(graph, user_pri) # runs algorithm that finds the prioritize paths
    create_table(db, prioritize_lists, data_list)

    net_flow_graph = make_net_flow_graph(graph, tac_graph)

    # translates networkx graph into PyViz graph
    g1.from_nx(graph)
    g1.force_atlas_2based() # changing the layout of the graph
    g1.show('/templates/graph.html')

    # translates network flow graph into PyViz graph
    g2.from_nx(net_flow_graph)
    g2.force_atlas_2based() # changing the layout of the graph
    g2.show('/templates/network_flow.html')

# method to sort the individual priority lists
def sort_list(a_list):
    return sorted(a_list, key=lambda tup: tup[1], reverse=False)  # lambda arguments : expression


# finds priority of tactic
def show_prioritize(graph, user_pri):
    # priority of tactic
    high = []
    mid = []
    low = []

    # iterate over every node in the graph
    for node in graph.__iter__():
        # if its a tactic node
        if 'tactic' in node:
            # start the edge type counters
            cnt_tac = 0
            cnt_tech = 0

            # if the tactic is the one that user specified make it the most prioritize node
            if user_pri != None and user_pri in node:
                high.append((node, 0))
            else:
                for neighbor in graph.neighbors(node):
                    if 'technique' in neighbor:
                        # add a technique edge
                        cnt_tech += 1
                    else:
                        # add a tactic edge
                        cnt_tac += 1
                # sort the nodes into high, mid, and low priority based on tactic to tactic connectivity
                match cnt_tac:
                    case 0:
                        low.append((node, cnt_tech))
                    case 1:
                        mid.append((node, cnt_tech))
                    case _:
                        high.append((node, cnt_tech))
    # sort the individual lists
    low = sort_list(low)
    mid = sort_list(mid)
    high = sort_list(high)

    # determine the highest priority node and change color to red
    print('Low:', low, "\nMid:", mid, "\nHigh:", high)
    if high.__len__() > 0 and graph.has_node(high[0][0]):
        graph.add_node(high[0][0], color='red')
    elif mid.__len__() > 0 and graph.has_node(mid[0][0]):
        graph.add_node(mid[0][0], color='red')
    elif low.__len__() > 0 and graph.has_node(low[0][0]):
        graph.add_node(low[0][0], color='red')
    else:
        pass

    # returns a list that has all prioritize lists
    return high + mid + low


# creates a html table that contains data related to the generated graphs
def create_table(db, prioritize_lists, data_list):
    table_list = [] # will contains data for each table

    # loop to find the technique that map to the specific tactic
    for obj in prioritize_lists:
        tactic_id = obj[0]

        # finds technique(s) that map from the specific tactic
        query = 'for tac_tech in TacticTechnique '\
            + 'filter tac_tech._from == @tac_id '\
            + 'return distinct tac_tech._to'
        
        bind_var = {'tac_id': tactic_id}
        cursor = db.aql.execute(query, bind_vars=bind_var)

        # checks whether the technique is in the graph
        for tech_id in cursor:
            for data in data_list:
                if tech_id == data['Technique ID']:
                    
                    query = 'for tac in tactic '\
                    + 'filter tac._id == @tactic_id '\
                    + 'return tac.name'
                
                    bind_var = {'tactic_id': tactic_id}
                    cursor_tac = db.aql.execute(query, bind_vars=bind_var)
                    
                    tactic = tactic_id + ' (' + next(cursor_tac) + ')'
                    table_list.append({tactic:data})
                    break

    # creates and adds the json objects to the file
    with open('needed_controls.json', 'w') as out_file:
        json.dump(table_list, out_file, indent=2)
    
    # creates html table by using the json file that just generated
    with open('needed_controls.json', 'r') as out_file:
        json_objects = json.load(out_file)
        with open('/templates/table.html', 'w') as control_html:
            table_detail = '<ul><li>Code analysis has revealed that the system has the '\
                        + 'vulnerabilities identified by their CVE ids.</li><li>Each vulnerability'\
                        + ' found is followed by the attack technique that can be used to exploit '\
                        + 'that vulnerability.</li><li>The attack stage id that an adversary could'\
                        + ' achieve by exploiting the vulnerability with the attack technique is '\
                        + 'given on the left.</li><li>Also shown are the set of security controls '\
                        + 'suggested to mitigate the system\'s exposure to the specified attack '\
                        + 'technique.</li></ul>'
            
            table_head = '<head>\
      <!-- Required meta tags -->\
    <meta charset="utf-8">\
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">\
    <!-- Bootstrap CSS -->\
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/css/bootstrap.min.css" integrity="sha384-TX8t27EcRE3e/ihU7zmQxVncDAy5uIKz4rEkgIXeMed4M0jlfIDPvg6uqKI2xXr2" crossorigin="anonymous">\
    </head>'


            table_navigation_bar = '<nav class="navbar navbar-expand-md navbar-dark bg-dark">\
      <a class="navbar-brand" href="#">SSP Manager</a>\
       <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">\
        <span class="navbar-toggler-icon"></span>\
       </button>\
      <div class="collapse navbar-collapse" id="navbarNav">\
        <ul class="navbar-nav mr-auto">\
            <li class="nav-item active">\
                <a class="nav-link" href="#">Home <span class="sr-only">(current)</span></a>\
            </li>\
            <li class="nav-item">\
                <a class="nav-link" href="#">Results</a>\
            </li>\
        </ul>\
        <ul class="navbar-nav">\
            <li class="nav-item">\
                <a class="nav-link" href="#">Login</a>\
            </li>\
            <li class="nav-item">\
                <a class="nav-link" href="#">Register</a>\
            </li>\
        </ul>\
      </div>\
    </nav>'

            control_html.write(table_head + table_navigation_bar + '<h1>Table</h1><div>' + table_detail + '</div><style>body {background-color: #212121; color: white;}h1 '
                               + '{text-align: center;} div {text-align: center;} ul {display: '
                               + 'inline-block; text-align: left;}</style>')
            for obj in json_objects:
                build_direction = "LEFT_TO_RIGHT"
                table_attributes = {"width": 100, "align" : "center", "border": 1}
                html = json2table.convert(obj, build_direction=build_direction, 
                                          table_attributes=table_attributes)
                control_html.write(html)


# creates a network flow graph
def make_net_flow_graph(graph, tac_graph):
    net_flow_graph= nx.DiGraph()
    SRC = 'source[s]' # starting point of the graph
    SINK = 'sink[t]' # ending point of the graph

    # prepares unique nodes for the graph
    nodes = [[SRC]] # starting node
    for n in tac_graph.__iter__(): # gets tactic in order of path
        tech = []
        neighbors = graph.neighbors(n)
        for node in neighbors: # loops to get all techniques
            if 'technique' in node:
                tech.append(n.split('/')[-1] + '/' + node.split('/')[-1]) # assigns unique name
        nodes.append(tech)
    nodes.append([SINK]) # ending node

    # adds nodes and edges to the network flow graph
    for i in range(len(nodes)-1):
        for j in range(len(nodes[i])):
            net_flow_graph.add_node(nodes[i][j])

            # checks what capacity to set
            if nodes[i][j] == 'source[s]':
                capa = len(nodes[i+1])
            else:
                capa = len(nodes[i])
            for k in range(len(nodes[i+1])):
                net_flow_graph.add_edge(nodes[i][j], nodes[i+1][k], capacity=capa, title=capa)
    
    return net_flow_graph


# TODO: decide the place to call this function
# creates a json file that contains all simple paths of network flow graph
def create_simple_paths_json(net_flow_graph, src, sink):
    simple_paths = [] # lists that will hold the json objects
    for path in nx.all_simple_paths(net_flow_graph, src, sink):
        simple_paths.append({'path': path})
    
    # creates and adds the json objects to the file
    with open('net_flow_graph.json', 'w') as out_file:
        json.dump(simple_paths, out_file, indent=2)
