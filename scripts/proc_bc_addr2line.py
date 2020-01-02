#!/usr/bin/env python

import re
import subprocess
import sys

genhtml = True

CODE_ADDR_START = 0xffffffff817659c0
CODE_ADDR_END = 0xffffffff8205353b

DEFAULT_FNAME = "./s2e-last/debug.txt"

p_addr = re.compile("0x[0-9A-Fa-f]{16}")
p_bc = re.compile("0x[0-9A-Fa-f]{16} -> 0x[0-9A-Fa-f]{16}: \d+")

cache = {}

def in_range(addr):
    return addr >= CODE_ADDR_START and addr <= CODE_ADDR_END

def addr2line(matchobj):
    addr = matchobj.group(0)
    if addr in cache:
        return cache[addr]

    result = subprocess.check_output("addr2line -f -i -e guestfs/vmlinux %s" % addr, shell=True)
    lines = result.strip().split('\n')
    funcname = lines[-2]
    srcfile, lineno = lines[-1].split(':')
    srcfile = '/'.join(srcfile.split('/')[10:])
    repl_str = srcfile + ':' + lineno + '(' + funcname + ')'
    if genhtml:
        repl_str = '<a href="/source/%s?lineno=%s" target="_blank">%s</a>' % (srcfile, lineno, repl_str)
    cache[addr] = repl_str
    return repl_str


fname = DEFAULT_FNAME

if len(sys.argv) == 2:
    fname = sys.argv[1]

f = open(fname, 'r')

if genhtml:
    print("<html>")

for line in f:
    line = line.rstrip()
    if "BranchCoverage:" in line:
        line = p_addr.sub(addr2line, line)
    elif p_bc.match(line):
        line = p_addr.sub(addr2line, line)
    if genhtml:
        print("%s<br>" % line)
    else:
        print(line)

f.close()

if genhtml:
    print("</html>")

