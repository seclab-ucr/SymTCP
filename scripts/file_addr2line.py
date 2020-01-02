#!/usr/bin/env python

import re
import subprocess
import sys

p_addr_str = "0x[0-9a-fA-F]{16}"
p_addr = re.compile(p_addr_str)

genhtml = False

VMLINUX_PATH = "guestfs/vmlinux"


cache = {}

outterMost = True


def addr2line(matchobj):
    addr = matchobj.group(0)
    if addr in cache:
        return cache[addr]

    result = subprocess.check_output("addr2line -f -i -e %s %s" % (VMLINUX_PATH, addr), shell=True)
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
    if genhtml:
        repl_str = '<a href="/source/%s?lineno=%s" target="_blank">%s</a>' % (srcfile, lineno, repl_str)
    cache[addr] = repl_str
    return repl_str


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Convert all addresses appeared in a file to source code lines.')
    parser.add_argument('file_path', type=str, help='Text file path')
    parser.add_argument('-o', dest='outter_most', default=False, action='store_true', help='Use outter-most level of source code information')
    args = parser.parse_args()

    outterMost = args.outter_most
    f = open(args.file_path, 'r')
    content = f.read()
    f.close()

    output = p_addr.sub(addr2line, content)

    f = open(args.file_path + '.translated', 'w')
    f.write(output)
    f.close()


