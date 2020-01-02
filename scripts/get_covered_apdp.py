#!/usr/bin/env python

import os
import re
import subprocess
import sys

# log entry: "Terminating state early: Reached drop edge of interest: 0xffffffff8178fffd->0xffffffff817900d1"
#pattern = re.compile("Terminating state early: (Reached drop (edge|instruction) of interest: (.*))")
# log entry: "Accept points reached: ....", "Drop points reached: ..."
pattern = re.compile(" (Accept|Drop) points reached: (.*)")

if len(sys.argv) == 2:
    s2e_result_dir = sys.argv[1]
else:
    s2e_result_dir = 's2e-last'


if os.path.exists(s2e_result_dir + "/debug.txt"):
    # single-process
    output = subprocess.check_output("grep -e 'Accept points reached: ' -e 'Drop points reached: ' " + s2e_result_dir + "/debug.txt", shell=True)
else:
    # multi-process
    output = subprocess.check_output("grep -e 'Accept points reached: ' -e 'Drop points reached: ' " + s2e_result_dir + "/*/debug.txt", shell=True)

lines = output.rstrip().split('\n')

fa = open(s2e_result_dir + '/covered_ap.raw', 'w')
fd = open(s2e_result_dir + '/covered_dp.raw', 'w')

for line in lines:
    m = pattern.search(line)
    if m:
        accept_or_drop = m.group(1)
        if accept_or_drop == 'Accept':
            for ap in m.group(2).split():
                fa.write(ap + '\n')
        elif accept_or_drop == 'Drop':
            for dp in m.group(2).split():
                fd.write(dp + '\n')
                break
        else:
            assert False

fa.close()
fd.close()

os.system("sort " + s2e_result_dir + "/covered_ap.raw | uniq > " + s2e_result_dir + "/covered_ap")
os.system("sort " + s2e_result_dir + "/covered_dp.raw | uniq > " + s2e_result_dir + "/covered_dp")

