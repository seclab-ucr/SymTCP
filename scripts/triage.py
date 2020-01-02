#!/usr/bin/env python

# Find satisfied/unsatisfied branches based on static analysis results
# We may need to further look at unvisited branches that static analysis marked as feasible 


import os
import re
import subprocess
import sys


pattern1 = re.compile("[0-9]+ \[State ([0-9]+)\] BranchDirector: \[BD\] execute branch: (.*?) -> .*")
pattern2 = re.compile("[0-9]+ \[State ([0-9]+)\] BranchDirector: \[BD\] Branch should be avoided: (.*?), actual branch taken: (.*?) \((.*)\)")
pattern3 = re.compile("[0-9]+ \[State ([0-9]+)\] \[WZJ\] Current PC: (.*)")
pattern4 = re.compile("[0-9]+ \[State ([0-9]+)\] Forking state ")

SOURCE_PREFIX = "/home/alan/Work/source/lll-49/"
EXT_SOURCE_PREFIX = "/home/alan/Work/extraspace/s2e/images/.tmp-output/linux-4.9.3-x86_64/linux-4.9.3/"


"""
line_info = {}

def get_line_info_old(pc):
    while pc not in line_info:
        pc -= 1
    return line_info[pc]
"""

def get_line_info(addrs):
    if not addrs:
        return {}
    if not isinstance(addrs, list):
        addrs = [ addrs ]
    line_infos = {}
    addrs_strs = ' '.join(addrs)
    output = subprocess.check_output("addr2line -a -i -e ~/Work/extraspace/s2e/kernel/vmlinux %s" % addrs_strs, shell=True)
    #print(output)
    output = output.split('\n')
    for line in output:
        line = line.rstrip()
        if line:
            parts = line.split(':')
            if len(parts) == 2:
                if parts[0].startswith(SOURCE_PREFIX):
                    parts[0] = parts[0][len(SOURCE_PREFIX):]
                elif parts[0].startswith(EXT_SOURCE_PREFIX):
                    parts[0] = parts[0][len(EXT_SOURCE_PREFIX):]
                line_infos[curr_addr].append(tuple(parts))
            else:
                curr_addr = int(line, 16)
                if curr_addr not in line_infos:
                    line_infos[curr_addr] = []
    return line_infos
                

def triage(s2e_log_file, eliminate_dead_branches=True):
    branches_hit = {}
    state_branches = {}
    dead_branches = {}

    f = open(s2e_log_file, 'r')

    proc_branch = False
    forking_state = 0
    branch_pc = None
    for line in f:
        line = line.rstrip()
        #print(line)
        if proc_branch:
            proc_branch = False
            m = pattern2.match(line)
            #assert m
            if m:
                state_id = m.group(1)
                next_pc = m.group(2)
                branch_taken = m.group(3)
                yes_or_no = m.group(4)
                state_branches[state_id][-1][1] = branch_taken
                if yes_or_no == "Yes":
                    branches_hit[branch_pc][0] += 1
                    state_branches[state_id][-1][2] = 0
                elif yes_or_no == "No":
                    branches_hit[branch_pc][1] += 1
                    state_branches[state_id][-1][2] = 1
                else:
                    assert False
                if next_pc == "0x0":
                    dead_branches[branch_pc] = True
                branch_pc = None
                continue
            branch_pc = None


        if forking_state:
            state_id = line.split()[1]
            if state_id != forking_state_id:
                state_branches[state_id] = list(state_branches[forking_state_id])
            forking_state  = (forking_state + 1) % 3

        else:
            m = pattern4.match(line)
            if m:
                state_id = m.group(1)
                forking_state_id = state_id
                forking_state = 1
                continue

            m = pattern3.match(line)
            if m:
                state_id = m.group(1)
                branch_pc = m.group(2)
                if state_id not in state_branches:
                    state_branches[state_id] = []
                state_branches[state_id].append([branch_pc, None, -1])
                continue

            m = pattern1.match(line)
            if m:
                state_id = m.group(1)
                branch_pc = m.group(2)
                if state_id not in state_branches:
                    state_branches[state_id] = []
                if branch_pc not in branches_hit:
                    branches_hit[branch_pc] = [0, 0] # [yes, no]
                if not state_branches[state_id] or state_branches[state_id][-1][0] != branch_pc:
                    state_branches[state_id].append([branch_pc, None, -1])
                proc_branch = True
                continue

    f.close()

    yes_branches = []
    no_branches = []
    never_branches = []
    for branch_pc, cnt in branches_hit.iteritems():
        if eliminate_dead_branches:
            if branch_pc in dead_branches:
                continue

        yesed = False
        if cnt[0] > 0: # has yes
            yes_branches.append((branch_pc, cnt[0]))
            yesed = True
        if cnt[1] > 0: # has no
            no_branches.append((branch_pc, cnt[1]))
            if not yesed:
                # only has no
                never_branches.append((branch_pc, cnt[1]))


    sorted_yes = sorted(yes_branches, key=lambda (a,b): b, reverse=True)
    sorted_no = sorted(no_branches, key=lambda (a,b): b, reverse=True)
    sorted_never = sorted(never_branches, key=lambda (a,b): b, reverse=True)

    return sorted_yes, sorted_no, sorted_never


if __name__ == "__main__":
    if len(sys.argv) == 2:
        log_file_path = sys.argv[1]
    else:
        log_file_path = "/home/alan/Work/extraspace/s2e/projects/tcp/s2e-last/debug.txt"

    yes_branches, no_branches, never_branches = triage(log_file_path)

    print("----------------------------")
    print("Yes branches:")
    addrs = [ branch_pc for branch_pc, cnt in yes_branches ]
    line_infos = get_line_info(addrs)
    for branch_pc, cnt in yes_branches:        
        branch_pc_i = int(branch_pc, 16)
        #print("%s %d %s" % (branch_pc, cnt, get_line_info(branch_pc_i)))
        print("%s %d %s" % (branch_pc, cnt, line_infos[branch_pc_i]))

    print("----------------------------")
    print("No branches:")
    addrs = [ branch_pc for branch_pc, cnt in no_branches ]
    line_infos = get_line_info(addrs)
    for branch_pc, cnt in no_branches:        
        branch_pc_i = int(branch_pc, 16)
        print("%s %d %s" % (branch_pc, cnt, line_infos[branch_pc_i]))

    print("----------------------------")
    print("Never branches:")
    addrs = [ branch_pc for branch_pc, cnt in never_branches ]
    line_infos = get_line_info(addrs)
    for branch_pc, cnt in never_branches:        
        branch_pc_i = int(branch_pc, 16)        
        print("%s %d %s" % (branch_pc, cnt, line_infos[branch_pc_i]))

