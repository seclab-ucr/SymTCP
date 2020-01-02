#!/usr/bin/env python

import os
import sys

from s2e_utils import *


FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

def tcp_flags_to_string(tcp_flags):
    assert len(tcp_flags) == 1
    tcp_flags = tcp_flags[0]
    res = ""
    if tcp_flags & SYN:
        res += "S"
    if tcp_flags & ACK:
        res += "A"
    if tcp_flags & FIN:
        res += "F"
    if tcp_flags & RST:
        res += "R"
    if tcp_flags & PSH:
        res += "P"
    if tcp_flags & URG:
        res += "U"
    if tcp_flags & ECE:
        res += "E"
    if tcp_flags & CWR:
        res += "C"
    return res


f = open(sys.argv[1], 'r')

for line in f:
    cc = eval(line)
    tcp_flags = []
    for var in cc['example']:
        if 'tcp_flags' in var:
            pkt_idx, _ = get_packet_idx(var)
            tcp_flags.append((pkt_idx, cc['example'][var]))
    tcp_flags = sorted(tcp_flags, key=lambda x: x[0])
    tcp_flags_strs = [ tcp_flags_to_string(tcp_flag) for pkt_idx, tcp_flag in tcp_flags ]
    print(",".join(tcp_flags_strs))

f.close()

