#!/usr/bin/env python

import sys

from s2e_utils import *


TCP_STATE_STR = {
    0: "N/A",
    1: "TCP_ESTABLISHED",
    2: "TCP_SYN_SENT",
    3: "TCP_SYN_RECV",
    4: "TCP_FIN_WAIT1",
    5: "TCP_FIN_WAIT2",
    6: "TCP_TIME_WAIT",
    7: "TCP_CLOSE",
    8: "TCP_CLOSE_WAIT",
    9: "TCP_LAST_ACK",
    10: "TCP_LISTEN",
    11: "TCP_CLOSING",
    12: "TCP_NEW_SYN_RECV",
    13: "TCP_MAX_STATES"
}


dp_map = {}
ap_map = {}
skstate_map = {}
pktnum_map = {}

f = open(sys.argv[1], 'r')

for line in f:
    entry = eval(line)
    for dp in entry['drop_points']:
        if dp not in dp_map:
            dp_map[dp] = 0
        dp_map[dp] += 1
        break
    for ap in entry['accept_points']:
        if ap not in ap_map:
            ap_map[ap] = 0
        ap_map[ap] += 1
    sk_state = entry['sk_state'][entry['packet_num']]
    if sk_state not in skstate_map:
        skstate_map[sk_state] = 0
    skstate_map[sk_state] += 1

    packet_num = entry['packet_num']
    if packet_num not in pktnum_map:
        pktnum_map[packet_num] = 0
    pktnum_map[packet_num] += 1

f.close()

print("------------Drop point (%d)-----------" % len(dp_map))

for dp in dp_map:
    print("%d\t%s" % (dp_map[dp], dp))

print("------------Accept point (%d)-----------" % len(ap_map))

for ap in ap_map:
    print("%d\t%s" % (ap_map[ap], ap))

print("------------Socket state-----------")

for sk_state in skstate_map:
    print("%d\t%s" % (skstate_map[sk_state], TCP_STATE_STR[sk_state]))

print("------------Packet num-----------")

for packet_num in pktnum_map:
    print("%d\t%d" % (pktnum_map[packet_num], packet_num))


