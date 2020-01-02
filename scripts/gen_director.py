#!/usr/bin/env python

import os
import sys


#targetaddr_file = sys.argv[1]
callchain_file = sys.argv[1]
blacklist_file = sys.argv[2]
idx = int(sys.argv[3])


OFFSET = 0xb9757390


"""
f0 = open(targetaddr_file, 'r')
target_addr = int(f0.read().strip(), 16)
if target_addr:
    target_addr += OFFSET
f0.close()
"""

callchain = []


def is_in_callchain(start_ea, end_ea):
    for _, s, e in callchain:
        if s == start_ea and e == end_ea:
            return True
    return False


f1 = open(callchain_file, 'r')

assert idx >= 0
i = 0
for line in f1:
    if i == idx:
        line = line.rstrip()
        for step in line.split('|'):
            func_name, start_ea, end_ea = step.split(',')
            start_ea = int(start_ea, 16)
            end_ea = int(end_ea, 16)
            # memory address: built-in.o -> vmlinux
            if start_ea != 0:
                start_ea += OFFSET
            if end_ea != 0:
                end_ea += OFFSET
            callchain.append((func_name, start_ea, end_ea))
        target_addr = callchain[-1][2]
        assert(target_addr)
        break

    i += 1

f1.close()

f2 = open(blacklist_file, 'r')

start_ea = end_ea = None
br_info = {}
content = ""
logging = False

for line in f2:
    if line.startswith('[Start]'):
        line = line.rstrip()
        parts = line.split()
        start_ea = int(parts[3], 16)
        end_ea = int(parts[5], 16)
        # memory address: built-in.o -> vmlinux
        if start_ea != 0:
            start_ea += OFFSET
        if end_ea != 0:
            end_ea += OFFSET
        if is_in_callchain(start_ea, end_ea):
            logging = True
            content = ""
    elif line.startswith('[End]'):
        if logging:
            k = "%x-%x" % (start_ea, end_ea)
            br_info[k] = content
        logging = False
    else:
        if logging:
            parts = line.split(':')
            if len(parts) == 2:
                br_pc = int(parts[0], 16)
                br_pc += OFFSET
                if parts[1].strip():
                    subparts = parts[1].split()
                    content += "%x:" % br_pc
                    for subp in subparts:
                        next_pc = int(subp, 16)
                        if next_pc:
                            next_pc += OFFSET
                        content += " %x" % next_pc
                    content += "\n"
                else:
                    content += "%x:\n" % br_pc

f2.close()

print("target = %x" % target_addr)

for f, s, e in callchain:
    if e != 0:
        k = "%x-%x" % (s, e)
        print("%s from %x to %x" % (f, s, e))
        if e != 0:
            assert k in br_info, "Branch info doesn't exsit. %s" % k
            print(br_info[k])
        else:
            print("")


