#!/usr/bin/env python

f = open('s2e-last/debug.txt', 'r')

flag = False

for line in f:
    if flag:
        if line[0] != 'B':
            print line,
    else:
        if line.startswith("Uncovered branches"):
            flag = True

f.close()

