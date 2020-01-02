#!/usr/bin/env python

import subprocess
import sys

#tcp_start_offset = 0xa50ed6
#tcp_start_addr = 0
tcp_start_offset = 0x1089d7
tcp_start_addr = 0

found_fname = False
full_trace = False

traces = {}

BRO_PATH = '/usr/local/bro/bin/bro'
SNORT_PATH = '/home/alan/Work/source/snort-2.9.13/src/snort'

#ENTRY_FUNC = 'TCP_Analyzer::DeliverPacket'
ENTRY_FUNC = 'StreamProcessTcp'

cache = {}
outterMost = True


def addr2offset(addr):
    return addr - tcp_start_addr + tcp_start_offset

def addr2line(addr):
    if addr in cache:
        return cache[addr]

    #result = subprocess.check_output("addr2line -f -i -e %s %s" % (BRO_PATH, addr), shell=True)
    result = subprocess.check_output("addr2line -f -i -e %s %s" % (SNORT_PATH, addr), shell=True)
    result = result.decode('ascii')
    lines = result.strip().split('\n')
    if outterMost:
        funcname = lines[-2]
        srcfile, lineno = lines[-1].split(':')
    else:
        funcname = lines[0]
        srcfile, lineno = lines[1].split(':')
    #print(funcname)
    #print(srcfile + ':' + lineno)
    srcfile = '/'.join(srcfile.split('/')[7:])
    repl_str = srcfile + ':' + lineno + '(' + funcname + ')'
    #if genhtml:
    #    repl_str = '<a href="/source/%s?lineno=%s" target="_blank">%s</a>' % (srcfile, lineno, repl_str)
    cache[addr] = repl_str
    return repl_str


f = open(sys.argv[1], 'r')
for line in f:
    if found_fname:
        found_fname = False
        full_trace = True
    elif full_trace:
        full_trace = False
        trace = line.strip()
        if trace not in traces:
            traces[trace] = []
        traces[trace].append(fname)
    else:
        if line.startswith("('" + ENTRY_FUNC + "'"):
            tcp_start_addr = int(eval(line)[1], 16)
        elif line.startswith("packet_dump_"):
            fname = line.strip()
            found_fname = True
f.close()

print(len(traces))

for trace, fnames in traces.iteritems():
    print(fnames)
    trace = eval(trace)
    trace = [hex(addr2offset(int(addr, 16))) for addr in trace]
    print(trace)
    print('----------------------------------------')
    for offset in trace:
        print(addr2line(offset))
    print('----------------------------------------')
    raw_input('Press ENTER to continue...')



