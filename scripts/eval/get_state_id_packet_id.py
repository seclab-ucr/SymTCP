#!/usr/bin/env python

import os
import sys


flags = ['SYN', 'ACK', 'FIN', 'RST', 'FINACK', 'RSTACK']


pcaps_dir = sys.argv[1]

for fname in os.listdir(pcaps_dir):
    parts = fname.split('_')
    if parts[3] == 'c':
        state_id = '_'.join(parts[2:6])
    else:
        state_id = parts[2]
    packet_id = parts[-1].split('.')[0]
    tcp_flags = 'None'
    if parts[-2] in flags:
        tcp_flags = parts[-2]
    print("%s,%s,%s" % (state_id, packet_id, tcp_flags))


