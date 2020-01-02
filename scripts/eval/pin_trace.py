#!/usr/bin/env python

import subprocess
import sys

from select import select


TIMEOUT = 1


PIN_PATH = "/home/alan/Work/pin-3.10-97971-gc5e41af74-gcc-linux/pin"
PIN_TOOL_BRO_PATH = "/home/alan/Work/pin-3.10-97971-gc5e41af74-gcc-linux/source/tools/ToolUnitTests/obj-intel64/branch_target_addr_bro.so"
PIN_TOOL_SNORT_PATH = "/home/alan/Work/pin-3.10-97971-gc5e41af74-gcc-linux/source/tools/ToolUnitTests/obj-intel64/branch_target_addr_snort.so"

BRO_PATH = "/usr/local/bro/bin/bro"
BRO_RULE_PATH = "/home/alan/Work/extraspace/s2e/sym-tcp/tools/dpi_sys_confs/bro/detect-bad-keywords.bro"
BRO_ARGS = [BRO_PATH, '-C', '-i', 'lo', BRO_RULE_PATH]
BRO_ENTRY_FUNC = 'TCP_Analyzer::DeliverPacket'

SNORT_PATH = "/home/alan/Work/source/snort-2.9.13/src/snort"
SNORT_RULE_PATH = "/etc/snort/snort.conf"
SNORT_ARGS = [SNORT_PATH, '-c', SNORT_RULE_PATH, '-i', 'lo']
SNORT_ENTRY_FUNC = 'StreamProcessTcp'


def start_pin():
    #args = [PIN_PATH, '-t', PIN_TOOL_BRO_PATH, '--']
    args = [PIN_PATH, '-t', PIN_TOOL_SNORT_PATH, '--']
    #args += BRO_ARGS
    args += SNORT_ARGS
    print(args)
    pin_proc = subprocess.Popen(args, stdout=subprocess.PIPE)
    return pin_proc

def process(pin_proc):
    entry_addr = None
    in_session = False
    trace = []

    while True:
        rlist, _, _ = select([pin_proc.stdout], [], [], TIMEOUT)
        if rlist:
            line = rlist[0].readline()
            line = line.strip()
            if line.startswith('** found '):
                parts = line.split()
                func_name = parts[2]
                start_addr = parts[4]
                end_addr = parts[6]
                print(func_name, start_addr, end_addr)
                if func_name == SNORT_ENTRY_FUNC:
                    entry_addr = start_addr
            elif line.startswith('basic block executed'):
                if not in_session:
                    print("----------Session Start----------")
                    trace = []
                    in_session = True
                #print(line)
                bb_addr = line.split()[-1]
                trace.append(bb_addr)
        else:
            if in_session:
                print("----------Session End----------")
                f = open('fname', 'r')
                fname = f.read().strip()
                f.close()
                print(fname)
                print(trace)
                trace2 = []
                for bb_addr in trace:
                    if bb_addr == entry_addr:
                        trace2 = []
                    trace2.append(bb_addr)
                print(trace2)
                in_session = False

def main():
    pin_proc = start_pin()
    print("PIN started...")

    try:
        process(pin_proc)
    except:
        pin_proc.kill()


if __name__ == "__main__":
    main()


