#!/usr/bin/env python

import sys

d1 = {}

f = open(sys.argv[1], 'r')
for line in f:
    parts = line.strip().split()
    cnt = int(parts[0])
    pc = parts[1]
    d1[pc] = cnt
f.close()

diff = {}

f = open(sys.argv[2], 'r')
for line in f:
    parts = line.strip().split()
    cnt = int(parts[0])
    pc = parts[1]
    if pc not in d1:
        diff[pc] = cnt
    elif d1[pc] < cnt:
        diff[pc] = cnt - d1[pc]
f.close()

sorted_diff = sorted(diff.iteritems(), key=lambda x: x[1], reverse=True)

for k, v in sorted_diff:
    print("%d\t%s" % (v, k))






