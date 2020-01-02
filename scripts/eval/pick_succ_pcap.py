#!/usr/bin/env python

import os
import sys
import glob

from shutil import copyfile


PCAPS_DIR = './pcaps'
SUCC_PCAPS_DIR = './succ_pcaps'

SYN = 0x02
RST = 0x04
ACK = 0x10
FIN = 0x01

TCP_FLAGS_LST = {
    'SYN': SYN,
    'RST': RST,
    'ACK': ACK,
    'FIN': FIN,
    'RSTACK': RST | ACK,
    'FINACK': FIN | ACK
}


def get_succ_pcap_list(result_file):
    all_pcaps = {}
    succ_pcaps = []

    for fname in glob.glob(PCAPS_DIR + "/packet_dump_*.pcap"):
        fname = os.path.basename(fname)
        #print(fname)
        parts = fname.split('_')
        if parts[3] == 'c':
            state_id = '_'.join(parts[2:6])
        else:
            state_id = parts[2]
        packet_num = parts[-1].split('.')[0]
        if parts[-2] in TCP_FLAGS_LST:
            tcp_flags = parts[-2]
        else:
            tcp_flags = 'UNCONSTRAINED'
        if state_id not in all_pcaps:
            all_pcaps[state_id] = {}
        if packet_num not in all_pcaps[state_id]:
            all_pcaps[state_id][packet_num] = {}
        all_pcaps[state_id][packet_num][tcp_flags] = fname

    f = open(result_file, 'r')
    for line in f:
        state_id, packet_num, tcp_flags = line.rstrip().split(',')[:3]
        fname = all_pcaps[state_id][packet_num][tcp_flags]
        #print(fname)
        succ_pcaps.append(fname)
    f.close()

    return succ_pcaps


def copy_succ_pcaps(succ_pcaps):
    if not os.path.exists(SUCC_PCAPS_DIR):
        os.system("mkdir -p %s" % SUCC_PCAPS_DIR)
    for fname in succ_pcaps:
        copyfile(os.path.join(PCAPS_DIR, fname), os.path.join(SUCC_PCAPS_DIR, fname))


if __name__ == "__main__":
    result_file = sys.argv[1]
    succ_pcaps = get_succ_pcap_list(result_file)
    print(succ_pcaps)
    print(len(succ_pcaps))
    copy_succ_pcaps(succ_pcaps)



