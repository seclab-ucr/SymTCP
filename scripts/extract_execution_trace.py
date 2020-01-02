#!/usr/bin/env python

import os
import re
import subprocess
import sys

from s2e_utils import *

p_state_id_str = "\d+ \[.*State (\d+)\]"
p_state_id = re.compile(p_state_id_str)
p_c_state_id_str = "\s*state (\d+)"
p_c_state_id = re.compile(p_c_state_id_str)
p_fork_str = "(\d+) [^\n]+?Forking state (\d) at.*?\sstate (\d+).*?\sstate (\d+)"
p_fork = re.compile(p_fork_str, re.MULTILINE | re.DOTALL)
p_line_str = ": (onExecute|Entering|Leaving)"
p_line = re.compile(p_line_str)


s2e_out_dir = sys.argv[1]
sid = int(sys.argv[2])

s2e_output_files = get_s2e_output_files(s2e_out_dir)
reversed_fork_rel = get_reversed_fork_relations(s2e_output_files)

state_list = [ sid ]

while sid != 0:
    sid = reversed_fork_rel[sid]
    state_list.append(sid)

state_list.reverse()

print(state_list)

all_exec_lines = []
min_ts = 999999999999

state_debug_files = {}
forking_point = {}

for i in range(len(state_list)):
    sid = state_list[i]
    output = subprocess.check_output('grep "State %d\]" %s/*/debug.txt | cut -d: -f1 | sort | uniq' % (sid, s2e_out_dir), shell=True)
    if not output:
        print("Reached the end of the log.")
        break
    debug_files = output.strip().split('\n')
    debug_files = sorted(debug_files, key=lambda x: int(x.split('/')[1]))

    done = False
    for debug_file in debug_files:
        f = open(debug_file, 'r')
        lines = f.readlines()
        f.close()
        j = 0
        while j < len(lines):
            line = lines[j]
            m = p_state_id.match(line)
            if m:
                state_id = int(m.group(1))
                if state_id == sid:
                    #m = p_line.search(line)
                    #if m:
                    if 'onTranslateBlockEnd' not in line:
                        all_exec_lines.append(line)
                        print line,

                    if i < len(state_list) - 1:
                        # check forking
                        next_sid = state_list[i + 1]
                        if 'Forking state' in line:
                            #import pdb
                            #pdb.set_trace()
                            j += 1
                            line = lines[j]
                            m = p_c_state_id.match(line)
                            assert m
                            c1_state_id = int(m.group(1))
                            if c1_state_id == next_sid:
                                done = True
                                break
                            j += 1
                            line = lines[j]
                            m = p_c_state_id.match(line)
                            while not m:
                                j += 1
                                line = lines[j]
                                m = p_c_state_id.match(line)
                            c2_state_id = int(m.group(1))
                            if c2_state_id == next_sid:
                                done = True
                                break
                            #continue

            j += 1
        if done:
            break

#print(state_exec_lines)
#print(forking_point)




