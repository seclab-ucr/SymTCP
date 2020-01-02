#!/usr/bin/env python

import glob
import os
import sys

from s2e_utils import ACCEPT_POINTS, DROP_POINTS

PCAPS_DIR = './succ_pcaps'


import argparse
parser = argparse.ArgumentParser(description='Open the pcap files of succeeded test cases one-by-one.')
parser.add_argument('succ_list', type=str, help='Success list')
parser.add_argument('-T', '--result-file', default='results', type=str, help='Test case file')
args = parser.parse_args()

test_cases = {}

if args.result_file:
    f = open(args.result_file, 'r')
    for line in f:
        tc = eval(line)
        test_cases[tc['state_id']] = tc
    f.close()

f = open(args.succ_list, 'r')
for line in f:
    line = line.rstrip()
    state_id, packet_num, flags, kind = line.split(',')
    if flags == 'UNCONSTRAINED':
        pattern = '%s/packet_dump_%s_*_%s.pcap' % (PCAPS_DIR, state_id, packet_num)
        files = glob.glob(pattern)
        files = [ fname for fname in files if fname[-8].isdigit() ]
    else:
        pattern = '%s/packet_dump_%s_*_%s_%s.pcap' % (PCAPS_DIR, state_id, flags, packet_num)
        files = glob.glob(pattern)
    #print(files)
    if not files:
        # pcap doesn't exist
        continue
    assert(len(files) == 1)
    tc = test_cases.get(state_id)
    if tc:
        if test_cases[state_id]['drop_points']:
            dp = test_cases[state_id]['drop_points'][0]
            dp_explain = DROP_POINTS[dp]
        else:
            dp = 'None'
            dp_explain = 'None'
        ap = test_cases[state_id]['accept_points'][-1]
        print("PCAP file: %s" % files[0])
        print("State ID: %s" % state_id)
        print("Packet number: %s/%d (%s)" % (packet_num, test_cases[state_id]['packet_num'], kind))
        print("Drop point: %s" % dp)
        print("Drop point explain: %s" % dp_explain)
        print("Accept point: %s" % ap)
        print("Accept point explain: %s" % ACCEPT_POINTS[ap])
    os.system("wireshark " + files[0])
    raw_input("Press ENTER to continue...")
f.close()

