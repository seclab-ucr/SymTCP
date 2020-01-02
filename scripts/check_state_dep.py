#!/usr/bin/env python

from s2e_utils import *


s2e_output_files = get_s2e_output_files('s2e-last')
reversed_fork_rel = get_reversed_fork_relations(s2e_output_files)

f = open('tmp2', 'r')

for line in f:
    state_id = line.rstrip().split()[-1]
    state_id = int(state_id)

    #os.system('grep "state %d with" -B 1 -A 17 s2e-last/*/debug.txt' % state_id)
    os.system('grep "state %d with" -B 1 s2e-last/*/debug.txt' % state_id)

    """
    tmp = state_id
    flag = False
    while tmp != 0:
        if tmp in [132, 138, 164, 168, 172, 194]:
            flag = True
            break
        tmp = reversed_fork_rel[tmp]
    if flag:
        print("OK")
    else:
        print("ERR")
    """

f.close()

