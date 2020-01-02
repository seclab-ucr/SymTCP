#!/usr/bin/env python

import subprocess


targets = []

f = open('all_dp', 'r')
for line in f:
    target = line.rstrip().split(' ', 1)[0].split('->')[0]
    targets.append(target)
f.close()



print("pluginsConfig.BranchCoverage.CriticalBranches = {")
for target in targets:
    print('    ' + target[2:] + ' = {')
    output = subprocess.check_output("./findCallChainsAndCriticalBranch.py " + target, shell=True)
    output = output.split('\n')
    flag = False
    for line in output:
        if not line:
            continue
        if flag:
            print('        "' + line + '",')
        if "---Critical Branches---" in line:
            flag = True
            continue
    print('    },')
print("}")






