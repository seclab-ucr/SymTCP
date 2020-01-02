#!/usr/bin/env python

branch_taint = {}

f = open('s2e-last/debug.txt', 'r')

taint = None

for line in f:
    if taint:
        assert 'KLEE: WARNING: Current Pc:' in line
        branch_pc = line.split()[-1]
        branch_taint[branch_pc] = taint
        #print("Branch %s tainted with %s" % (branch_pc, taint))
        taint = None
    else:
        if line.startswith('KLEE: WARNING: Branch condition tainted'):
            taint = line.split()[-1]
            taint = taint[1:-1].split(',')
            #print(taint)

f.close()

print(branch_taint)

