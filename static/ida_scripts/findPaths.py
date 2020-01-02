
import idaapi



call_chains = []

# load call chains

file0 = AskFile(0, "*.txt", "Select input file")
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


def collect_trace(curr_path):
    sorted_path = sorted(curr_path.iteritems(), key=lambda (k,v): v[0]) # v[0] is level
    return [ (x[1][1], x[0]) for x in sorted_path ]    # x[1][1] is parent block startEA, x[0] is child block startEA


# Find all paths from start_ea to end_ea within a function, no loop (i.e. loop level=1)
def find_paths(start_ea, end_ea):
    if end_ea == 0: 
        return [], 0
    # get function entry
    func_entry = idc.GetFunctionAttr(start_ea, idc.FUNCATTR_START)
    func_entry2 = idc.GetFunctionAttr(end_ea, idc.FUNCATTR_START)
    # start_ea and end_ea should be in the same function
    assert func_entry == func_entry2
    print("Finding paths from %x to %x within '%s'" % (start_ea, end_ea, Name(func_entry)))
    
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
    curr_path = {start_bb.startEA: 0}
    path_cnt = [0] # hack: https://stackoverflow.com/questions/2609518/python-nested-function-scopes

    def _find_paths_forward(curr_bb, level):
        if curr_bb.startEA == end_bb.startEA:
            assert curr_bb.endEA == end_bb.endEA
            path = collect_trace(branches)
            #all_paths.append(path)
            path_cnt[0] += 1
            #print(path_cnt[0])
            fd1.write("|".join([ "%x,%x" % x for x in path]))
            fd1.write("\n")
            return

        succ_num =  curr_bb._fc._q.nsucc(curr_bb.id)    # accessing private field 
        if succ_num == 0:
            # path end
            return;
        elif succ_num == 1:
            # normal flow
            succ_bb = curr_bb._fc[curr_bb._fc._q.succ(curr_bb.id, 0)]    # get the only successor
            curr_path[succ_bb.startEA] = level
            _find_paths_forward(succ_bb, level)
            del curr_path[succ_bb.startEA]
        else:
            # branch
            for succ_bb in curr_bb.succs():
                if succ_bb.startEA not in curr_path:
                    level += 1
                    branches[succ_bb.startEA] = (level, curr_bb.startEA)
                    curr_path[succ_bb.startEA] = level
                    #print("l%d" % len(curr_path))
                    #path = generate_path()
                    #fd1.write("%s\n" % path)
                    _find_paths_forward(succ_bb, level)
                    del branches[succ_bb.startEA]
                    del curr_path[succ_bb.startEA]
                    level -= 1
                    #print("l%d" % len(curr_path))

        
    _find_paths_forward(start_bb, 0)

    print("Path num: %d" % path_cnt[0])
    return all_paths, path_cnt[0]
    

found = {}    


#call_chains = [[('tcp_v4_send_reset', 0x80270e0, 0x80273c3)]]

for cc in call_chains:
    for c in cc:
        if c in found:
            paths = found[c]
        else:
            paths, cnt = find_paths(c[1], c[2])
            found[c] = paths
            fd1.write("%s from %x to %x: %d\n" % (c[0], c[1], c[2], cnt))
        #print(paths)
        #fd1.write("%s\n" % paths)

fd1.close()



