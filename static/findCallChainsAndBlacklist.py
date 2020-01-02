#!/usr/bin/env python

import cPickle
import sys

from cfg import *


# tcp_v4_rcv
START_EA = 0xffffffff8178ffa0

# drop point
TARGET_EA = 0xffffffff817830eb


callgraph = None
cfg = None

f = open("callgraph.dump", 'r')
callgraph = cPickle.load(f)
f.close()

f = open("cfg.dump", 'r')
cfg = cPickle.load(f)
f.close()


entry_func = callgraph.get_node_by_name("tcp_v4_rcv")
target_func = callgraph.get_node_by_addr(TARGET_EA)

# debug output
print("Entry Function Address: %x" % entry_func.addr)
print("Entry Function Name: '%s'" % entry_func.name)
print("Marked Instruction Address: %x" % TARGET_EA)
print("Marked Instruction belongs to function '%s'" % target_func.name)


# There are 2 steps:
# 1. Find all possible call chains (no recursive, i.e. recursive level = 1)
# 2. Find all possible paths within each function in the call chain


# 1. Find all possible call chains (backwards)

all_call_chains = []

def convert_call_stack_to_call_chain(call_stack, reverse=False):
    call_chain = []
    sorted_call_stack = sorted(call_stack.iteritems(), key=lambda (k,v): v['level'], reverse=reverse)

    for k, v in sorted_call_stack:
        call_chain.append([k, v['start_ea'], v['call_site'], v['level']])

    # quickfix
    if reverse:
        for i in range(len(call_chain)):
            call_chain[i][3] = len(call_chain) - 1 - call_chain[i][3] 
    else:
        for i in range(len(call_chain)-1):
            call_chain[i][2] = call_chain[i+1][2]
        call_chain[-1][2] = 0

    return call_chain


def find_call_chain_backward(curr_func, target_func, call_stack, curr_level):
    if curr_func == target_func:
        all_call_chains.append(convert_call_stack_to_call_chain(call_stack, True))
        return

    for call_site, caller_addr in curr_func.callers:
        caller = callgraph.get_node_by_addr(caller_addr)
        if caller:
            if caller.name not in call_stack:
                curr_level += 1
                call_stack[caller.name] = {'level': curr_level, 'start_ea': caller.addr, 'call_site': call_site}
                find_call_chain_backward(caller, target_func, call_stack, curr_level)
                del call_stack[caller.name]
                curr_level -= 1



find_call_chain_backward(target_func, entry_func, {target_func.name: {'level': 0, 'start_ea': target_func.addr, 'call_site': TARGET_EA}}, 0)

for cc in all_call_chains:
    c_strs = []
    for func_name, start_ea, call_site, lvl in cc:
        c_strs.append("%s,%x,%x" % (func_name, start_ea, call_site))
    print('|'.join(c_strs))


# 2. Find all possible paths within each function in the call chain, no loop (i.e. loop level=1)
# start_ea has to be the start address of the function

def find_paths(func_name, start_ea, end_ea):
    if end_ea == 0: 
        return [], 0
    # get function entry
    func_entry = callgraph.get_node_by_addr(start_ea)
    func_entry2 = callgraph.get_node_by_addr(end_ea)
    # start_ea and end_ea should be in the same function
    assert func_entry == func_entry2
    print("[Start] %s from %x to %x" % (func_name, start_ea, end_ea))
    
    # find start basic block and end basic block
    start_bb = cfg.get_node_by_addr(start_ea)
    end_bb = cfg.get_node_by_addr(end_ea)
    #print(hex(start_bb.addr))
    #print(hex(end_bb.addr))
    assert start_bb and end_bb

    all_paths = []
    branches = {}
    all_branches = {}
    br_done = {}
    loop_edges = {}
    curr_path = {start_bb.addr: 0}
    branches_taken = {}
    path_cnt = [0] # hack: https://stackoverflow.com/questions/2609518/python-nested-function-scopes
    cter = [0]

    def _find_paths_forward(curr_bb, level):
        #print("enter %x\n" % curr_bb.addr)
        if curr_bb == end_bb:
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
            #fd1.write("return from %x\n" % curr_bb.addr)
            return

        succ_num =  len(curr_bb.succs)
        if succ_num == 0:
            # path end
            pass
        elif succ_num == 1:
            # normal flow
            succ_addr = curr_bb.succs[0]  # get the only successor
            if succ_addr not in curr_path:
                level += 1
                curr_path[succ_addr] = level
                succ_bb = cfg.get_node_by_addr(succ_addr)
                _find_paths_forward(succ_bb, level)
                del curr_path[succ_addr]
                level -= 1
        else:
            # branch
            br_ea = curr_bb.last_inst_addr
            
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
                #print("early return from %x\n" % curr_bb.addr)
                return

            for succ_addr in curr_bb.succs:
                all_branches[br_ea].append(succ_addr)
                if succ_addr not in curr_path:
                    level += 1
                    branches_taken[br_ea] = succ_addr
                    curr_path[succ_addr] = level
                    #print("l%d" % len(curr_path))
                    #path = collect_trace(curr_path)
                    #print("%s" % path)
                    succ_bb = cfg.get_node_by_addr(succ_addr)
                    _find_paths_forward(succ_bb, level)
                    del branches_taken[br_ea]
                    del curr_path[succ_addr]
                    level -= 1
                    #print("l%d" % len(curr_path))
                else:
                    # loop edge
                    loop_edges[br_ea] = succ_addr
            br_done[br_ea] = True
            #print("return from %x\n" % curr_bb.addr)
        

    _find_paths_forward(start_bb, 0)

    print("Path num: %d" % path_cnt[0])

    # Generate the branch blacklist
    #print(branches)
    for br, succs in branches.iteritems():
        if br in loop_edges:
            # ignore branches have loop edges
            continue
        if len(succs) == 0:
            print("%x: 0" % br)
        elif len(succs) == 1:
            # get branch that is not visited
            print("%x: %s" % (br, ' '.join([ "%x" % succ for succ in all_branches[br] if succ not in succs ])))

    print("[End] %s from %x to %x: %d\n" % (func_name, start_ea, end_ea, path_cnt[0]))

    return all_paths, path_cnt[0]


found = {}

for cc in all_call_chains:
    print("---Call chain starts---\n")
    for func_name, start_ea, call_site, lvl in cc:
        if (start_ea, call_site) in found:
            paths = found[(start_ea, call_site)]
        else:
            paths, cnt = find_paths(func_name, start_ea, call_site)
            found[(start_ea, call_site)] = paths
        sys.exit(0)
    print("---Call chain ends---\n")



