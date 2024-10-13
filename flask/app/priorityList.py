def show_prioritize(self, user_priority_BRONtacticID):
        # priority of tactic
        high = []
        mid = []
        low = []

        # iterate over every node in the graph
        for node in self.tacticsAndTechniquesGraph.__iter__():
            # if its a tactic node
            if 'tactic' in node:
                # start the edge type counters
                cnt_tac = 0
                cnt_tech = 0

                # if the tactic is the one that user specified, prioritize the node
                if user_priority_BRONtacticID != None and user_priority_BRONtacticID in node:
                    high.append((node, 0))
                    f = open('/shared/debug_input.txt', 'a')
                    f.write('User selected tactic: ' + user_priority_BRONtacticID + '\n') # This works
                    f.close()
                else:
                    for neighbor in self.tacticsAndTechniquesGraph.neighbors(node):
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
        
        # Save high list to file
        with open('/shared/high.txt', 'a') as out_file:
            for item in high: # item is a tuple, tactic ID, and some munber -> number of techniques that the tactic has as neighbors.
                out_file.write(str(item) + "\n")
            out_file.write("\n")
            out_file.close()
        
        
        
        
        # sort the individual lists
        low = self.sort_list(low)
        mid = self.sort_list(mid)
        high = self.sort_list(high)


        with open('/shared/high.txt', 'a') as out_file:
            for item in high:
                out_file.write(str(item) + "\n")
            out_file.write("\n")
            out_file.close()

        # determine the highest priority node and change color to red
        print('Low:', low, "\nMid:", mid, "\nHigh:", high)
        if high.__len__() > 0 and self.tacticsAndTechniquesGraph.has_node(high[0][0]):
            self.tacticsAndTechniquesGraph.add_node(high[0][0], color='red')
        elif mid.__len__() > 0 and self.tacticsAndTechniquesGraph.has_node(mid[0][0]):
            self.tacticsAndTechniquesGraph.add_node(mid[0][0], color='red')
        elif low.__len__() > 0 and self.tacticsAndTechniquesGraph.has_node(low[0][0]):
            self.tacticsAndTechniquesGraph.add_node(low[0][0], color='red')
        else:
            pass

        # returns a list that has all prioritize lists
        return high + mid + low