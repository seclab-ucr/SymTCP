
import idaapi
import pdb


call_chains = []
found = {}

# load call chains

file0 = AskFile(0, "callchains.txt", "Select call chain file")
fd0 = open(file0, 'r')

for line in fd0:
    parts = line.split('|')
    cc = []
    for c in parts:
        tmp = c.split(',')
        cc.append((tmp[0], int(tmp[1], 16), int(tmp[2], 16)))
    call_chains.append(cc)

fd0.close()

#print call_chains

file1 = AskFile(1, "*.txt", "Select output file")
fd1 = open(file1, 'w')


def get_last_inst(basic_block):
    return PrevHead(basic_block.endEA)

def collect_trace(curr_path):
    sorted_path = sorted(curr_path.iteritems(), key=lambda (k,v): (v,k)) # v[0] is level
    return [ (hex(x[0]), x[1]) for x in sorted_path ]

# Find all paths from start_ea to end_ea within a function, no loop (i.e. loop level=1)
def find_paths(func_name, start_ea, end_ea):
    if end_ea == 0: 
        return [], 0
    # get function entry
    func_entry = idc.GetFunctionAttr(start_ea, idc.FUNCATTR_START)
    func_entry2 = idc.GetFunctionAttr(end_ea, idc.FUNCATTR_START)
    # start_ea and end_ea should be in the same function
    assert func_entry == func_entry2
    print("Finding paths from %x to %x within '%s'" % (start_ea, end_ea, Name(func_entry)))
    fd1.write("[Start] %s from %x to %x\n" % (Name(func_entry), start_ea, end_ea))
    
    f = idaapi.FlowChart(idaapi.get_func(func_entry))
    # find start basic block and end basic block
    start_bb = end_bb = None
    for bb in f:
        if bb.startEA <= start_ea <= bb.endEA:
            start_bb = bb
        if bb.startEA <= end_ea <= bb.endEA:
            end_bb = bb
    assert start_bb and end_bb

    all_paths = []
    branches = {}
    all_branches = {}
    br_done = {}
    loop_edges = {}
    curr_path = {start_bb.startEA: 0}
    branches_taken = {}
    path_cnt = [0] # hack: https://stackoverflow.com/questions/2609518/python-nested-function-scopes
    cter = [0]

    def _find_paths_forward(curr_bb, level):
        #fd1.write("enter %x\n" % curr_bb.startEA)
        if curr_bb.startEA == end_bb.startEA:
            assert curr_bb.endEA == end_bb.endEA
            #path = collect_trace(curr_path)
            #all_paths.append(path)
            #print(path_cnt[0])
            #fd1.write("|".join([ "%x,%x" % x for x in path]))
            #fd1.write("\n")
            # record all the branches taken
            for p, c in branches_taken.iteritems():
                if c not in branches[p]:
                    branches[p][c] = 1
                else:
                    branches[p][c] += 1
            path_cnt[0] += 1
            #fd1.write("Found a path\n")
            #fd1.write("return from %x\n" % curr_bb.startEA)
            return

        succ_num =  curr_bb._fc._q.nsucc(curr_bb.id)    # accessing private field 
        if succ_num == 0:
            # path end
            pass
        elif succ_num == 1:
            # normal flow
            succ_bb = curr_bb._fc[curr_bb._fc._q.succ(curr_bb.id, 0)]    # get the only successor
            if succ_bb.startEA not in curr_path:
                level += 1
                curr_path[succ_bb.startEA] = level
                _find_paths_forward(succ_bb, level)
                del curr_path[succ_bb.startEA]
                level -= 1
        else:
            # branch
            br_ea = get_last_inst(curr_bb)
            
            if br_ea not in branches:
                branches[br_ea] = {}
                all_branches[br_ea] = []
            if br_ea not in br_done:
                br_done[br_ea] = False
            elif br_done[br_ea]:
                if len(branches[br_ea]) > 0:
                    # We already know this branch can reach the target
                    # get the number of path from this point to the target
                    num = 0
                    for _, n in branches[br_ea].iteritems():
                        num += n
                    path_cnt[0] += num
                    for p, c in branches_taken.iteritems():
                        if c not in branches[p]:
                            branches[p][c] = num
                        else:
                            branches[p][c] += num
                #fd1.write("early return from %x\n" % curr_bb.startEA)
                return

            for succ_bb in curr_bb.succs():
                all_branches[br_ea].append(succ_bb.startEA)
                if succ_bb.startEA not in curr_path:
                    level += 1
                    branches_taken[br_ea] = succ_bb.startEA
                    curr_path[succ_bb.startEA] = level
                    #print("l%d" % len(curr_path))
                    #path = collect_trace(curr_path)
                    #print("%s" % path)
                    _find_paths_forward(succ_bb, level)
                    del branches_taken[br_ea]
                    del curr_path[succ_bb.startEA]
                    level -= 1
                    #print("l%d" % len(curr_path))
                else:
                    # loop edge
                    loop_edges[br_ea] = succ_bb.startEA
            br_done[br_ea] = True
            #fd1.write("return from %x\n" % curr_bb.startEA)
        

    _find_paths_forward(start_bb, 0)

    print("Path num: %d" % path_cnt[0])

    # Generate the branch blacklist
    #print(branches)
    for br, succs in branches.iteritems():
        if br in loop_edges:
            # ignore branches have loop edges
            continue
        if len(succs) == 0:
            fd1.write("%x: 0\n" % br)
        elif len(succs) == 1:
            fd1.write("%x:" % br)
            # get branch that is not visited
            for succ in all_branches[br]:
                if succ not in succs:
                    fd1.write(" %x" % succ)
            fd1.write("\n")

    fd1.write("[End] %s from %x to %x: %d\n" % (func_name, start_ea, end_ea, path_cnt[0]))
    fd1.flush()

    return all_paths, path_cnt[0]
    


#call_chains = [[('tcp_v4_send_reset', 0x80270e0, 0x80273c3)]]

for cc in call_chains:
    fd1.write("---Call chain starts---\n")
    for c in cc:
        #if c in found:
        #    paths = found[c]
        #else:
            paths, cnt = find_paths(c[0], c[1], c[2])
            found[c] = paths
        #print(paths)
        #fd1.write("%s\n" % paths)
    fd1.write("---Call chain ends---\n")

fd1.close()



