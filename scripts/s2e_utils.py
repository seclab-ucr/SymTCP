#!/usr/bin/env python

import os
import re
import sys
import glob


DROP_POINTS = {
    '0xffffffff817830eb': 'tcp_input.c:3615: Challenge ACK (the ACK case)',
    '0xffffffff81781e37': 'tcp_input.c:3735: ACK number > server send next',
    '0xffffffff81781e72': 'tcp_input.c:3742: ACK number older than previous acks',
    '0xffffffff817841d6': 'tcp_input.c:4386: OFO packet data already received',
    '0xffffffff81784924': 'tcp_input.c:4501: OFO packet overlap',
    '0xffffffff817848e5': 'tcp_input.c:4515: OFO packet partial overlap',
    '0xffffffff8178442f': 'tcp_input.c:4547: OFO packet overlap',
    '0xffffffff81784128': 'tcp_input.c:4641: Empty data packet',
    '0xffffffff81783d5d': 'tcp_input.c:4716: End SEQ number <= rcv_nxt (Retrans)',
    '0xffffffff8177e0d7': 'tcp_input.c:5194: SEQ number < copied_seq (SEQ num too old)',
    '0xffffffff81783ae6': 'tcp_input.c:5265: PAWS check failed (Timestamp)',
    '0xffffffff817908b6': 'tcp_ipv4.c:1653: TCP MD5 option check failed',
    '0xffffffff8179152f': 'tcp_minisocks.c:620: Retransmitted SYN',
    '0xffffffff81791418': 'tcp_minisocks.c:709(1): PAWS check failed || SEQ out of window',
    '0xffffffff817914f1': 'tcp_minisocks.c:709(2): PAWS check failed || SEQ out of window',
    '0xffffffff8179167a': 'tcp_minisocks.c:756: TCP_DEFER_ACCEPT drop bare ACK',
    '0xffffffff81791601': 'tcp_minisocks.c:734: SYN or RST flag set (embryonic reset)',
    '0xffffffff81783e2c->0xffffffff81783d96': 'tcp_input.c:4657: Receive window is zero',
    '0xffffffff8178404a->0xffffffff81783d96': 'tcp_input.c:4729: SEQ >= rcv_nxt + window (out of window)',
    '0xffffffff817840f0->0xffffffff81783d96': 'tcp_input.c:4745: Receive window is zero',
    '0xffffffff817839de->0xffffffff817839e0': 'tcp_input.c:5284: Challenge ACK (SYN) (out-of-window)',
    '0xffffffff817839d9->0xffffffff81783a00': 'tcp_input.c:5291(1): SEQ out of window',
    '0xffffffff81783a51->0xffffffff81783a00': 'tcp_input.c:5291(2): SEQ out of window',
    '0xffffffff81783a5e->0xffffffff81783a00': 'tcp_input.c:5291(3): SEQ out of window',
    '0xffffffff817838e1->0xffffffff81783a00': 'tcp_input.c:5291(4): SEQ out of window',
    '0xffffffff81783985->0xffffffff817839f8': 'tcp_input.c:5325(1): Challenge ACK (RST)',
    '0xffffffff81783990->0xffffffff817839f8': 'tcp_input.c:5325(2): Challenge ACK (RST)',
    '0xffffffff81783a62->0xffffffff817839f8': 'tcp_input.c:5325(3): Challenge ACK (RST)',
    '0xffffffff81783a1e->0xffffffff81783a20': 'tcp_input.c:5333: Challenge ACK (SYN)',
    '0xffffffff81784aa2->0xffffffff81784a40': 'tcp_input.c:5453: Packet length < TCP header length',
    '0xffffffff81784cfa->0xffffffff81784a30': 'tcp_input.c:5487: TCP checksum error',
    '0xffffffff81784a2a->0xffffffff81784a30': 'tcp_input.c:5531(1): Packet size < TCP header length || TCP checksum error',
    '0xffffffff81784b29->0xffffffff81784a30': 'tcp_input.c:5531(2): Packet size < TCP header length || TCP checksum error',
    '0xffffffff81784b34->0xffffffff81784a50': 'tcp_input.c:5534: No RST and no SYN and no ACK flag',
    '0xffffffff81785467->0xffffffff81785543': 'tcp_input.c:5911: ACK flag set',
    '0xffffffff8178546f->0xffffffff8178538f': 'tcp_input.c:5914: RST flag set',
    '0xffffffff8178547f->0xffffffff8178538f': 'tcp_input.c:5918: SYN and FIN flags set',
    '0xffffffff81785477->0xffffffff8178538f': 'tcp_input.c:5925: No RST and no SYN and no ACK flag',
    '0xffffffff81785382->0xffffffff8178538f': 'tcp_input.c:5947: Fastopen tcp_check_req failed',
    '0xffffffff81785389->0xffffffff8178538f': 'tcp_input.c:5951: No RST and no SYN and no ACK flag',
    '0xffffffff81785675->0xffffffff8178538f': 'tcp_input.c:6141: SEQ >= rcv_nxt',
    '0xffffffff8178f011->0xffffffff8178f013': 'tcp_ipv4.c:1404: TCP checksum error',
    '0xffffffff8178fffd->0xffffffff817900d1': 'tcp_ipv4.c:1607: TCP header length < 20',
    '0xffffffff817902d6->0xffffffff817900de': 'tcp_ipv4.c:1609(1): TCP header length > TCP packet size',
    '0xffffffff817902e9->0xffffffff817900de': 'tcp_ipv4.c:1609(2): TCP header length > TCP packet size',
    '0xffffffff81790082->0xffffffff817900c4': 'tcp_ipv4.c:1617(1): TCP checksum error',
    '0xffffffff817900be->0xffffffff817900c4': 'tcp_ipv4.c:1617(2): TCP checksum error',
    '0xffffffff817904af->0xffffffff81790721': 'tcp_ipv4.c:1672: ACK number != server ISN + 1',
    '0xffffffff81790776->0xffffffff817904ed': 'tcp_ipv4.c:1690: TCP MD5 option check failed',
    '0xffffffff81791650->0xffffffff81791425': 'tcp_minisocks.c:745: No ACK flag',
}

ACCEPT_POINTS = {
    '0xffffffff8178453b': 'tcp_data_queue():tcp_input.c:4663: In sequence. In window. (Sock owned by user)',
    '0xffffffff81783e66': 'tcp_data_queue():tcp_input.c:4684: In sequence. In window.',
    '0xffffffff817845cb': 'tcp_data_queue_ofo():tcp_input.c:4461: OFO: Initial out of order segment',
    '0xffffffff81784629': 'tcp_data_queue_ofo():tcp_input.c:4477: OFO: Coalesce (seq == prev->end_seq)',
    '0xffffffff817843f9': 'tcp_data_queue_ofo():tcp_input.c:4533: OFO: Insert segment into RB tree',
    '0xffffffff8178062e': 'tcp_conn_request():tcp_input.c:6408: Enter SYN_RECV',
    '0xffffffff817916d3': 'tcp_check_req():tcp_minisocks.c:773: Enter ESTABLISHED',
}


fork_pattern = re.compile("Forking state (\d+) at pc .*?\n\s*state (\d+).*?\s*state (\d+)", re.MULTILINE | re.DOTALL)

def get_s2e_output_files(s2e_out_dir):
    if os.path.exists(s2e_out_dir + "/debug.txt"):
        # single-process
        return [ s2e_out_dir + "/debug.txt" ]
    elif os.path.exists(s2e_out_dir + "/0/debug.txt"):
        # multi-process
        fnames = glob.glob(s2e_out_dir + "/*/debug.txt")
        return fnames
    else:
        # cannot find debug.txt
        return []

# find the fork relations between states
# e.g. state 0 fork into state 0 and 1,
# state 1 fork into state 1 and 2, then later fork into state 1 and 3.
# fork_rel = { 0: [1], 1: [2, 3], ... }
def get_fork_relations(s2e_output_files):
    fork_rel = {}
    for fname in s2e_output_files:
        f = open(fname, 'r')
        content = f.read()
        f.close()
        for m in fork_pattern.finditer(content):
            parent = m.group(1)
            if m.group(2) == parent:
                child = m.group(3)
            else:
                child = m.group(2)
            parent = int(parent)
            child = int(child)
            if parent not in fork_rel:
                fork_rel[parent] = []
            fork_rel[parent].append(child)

    return fork_rel

# find the reversed fork relations between states
# e.g. state 0 fork into state 0 and 1,
# state 1 fork into state 1 and 2, then later fork into state 1 and 3.
# reversed_fork_rel = { 1: 0, 2: 1, 3: 1, ... }
def get_reversed_fork_relations(s2e_output_files):
    reversed_fork_rel = {}
    for fname in s2e_output_files:
        f = open(fname, 'r')
        content = f.read()
        f.close()
        for m in fork_pattern.finditer(content):
            parent = m.group(1)
            if m.group(2) == parent:
                child = m.group(3)
            else:
                child = m.group(2)
            parent = int(parent)
            child = int(child)
            reversed_fork_rel[child] = parent

    return reversed_fork_rel

def prettyprint_fork_relations(fork_rel):
    keys = sorted(fork_rel.keys())
    for k in keys:
        values = [ str(v) for v in sorted(fork_rel[k]) ]
        print('%d: %s' % (k, ' '.join(values)))

def prettyprint_reversed_fork_relations(reversed_fork_rel):
    keys = sorted(reversed_fork_rel.keys())
    for k in keys:
        print('%d: %d' % (k, reversed_fork_rel[k]))

def get_derived_states(fork_rel, state_id):
    derived_states = []
    new_states = fork_rel.get(state_id)
    while new_states:
        derived_states += new_states
        new_states2 = []
        for s in new_states:
            if s in fork_rel:
                new_states2 += fork_rel[s]
        new_states = new_states2
    return derived_states

# get the appended packet index in the keyword. e.g. for v0_tcp_seq_num1_0, return 1 and tcp_seq_num.
def get_packet_idx(k):
    k = '_'.join(k.split('_')[1:-1])
    idx = 0
    for i in range(len(k)-1,-1,-1):
        if k[i].isdigit():
            idx = idx * 10 + int(k[i])
        else:
            break
    remaining = k[:-len(str(idx))]
    return idx, remaining

# get the number of packets from concrete example
def get_packet_num(ce):
    packet_num = 0
    for k in ce:
        packet_idx, _ = get_packet_idx(k)
        if packet_idx > packet_num:
            packet_num = packet_idx
    return packet_num

# big-endian
def int2bytes_be(val, size):
    v = []
    while val != 0:
        v.append(val % 256)
        val /= 256
    v += [0] * (size - len(v))
    v.reverse()
    return v

# big-endian
def bytes2int_be(v):
    val = 0
    for i in range(len(v)):
        val <<= 8
        val += v[i]
    return val

# little-endian
def int2bytes_le(val, size):
    v = []
    while val != 0:
        v.append(val % 256)
        val /= 256
    v += [0] * (size - len(v))
    return v

# little-endian
def bytes2int_le(v):
    val = 0
    for i in range(len(v) - 1, -1, -1):
        val <<= 8
        val += v[i]
    return val


if __name__ == "__main__":
    # test cases
    if len(sys.argv) == 2:
        s2e_out_dir = sys.argv[1]
    else:
        s2e_out_dir = 's2e-last'
    s2e_output_files = get_s2e_output_files(s2e_out_dir)
    fork_rel = get_fork_relations(s2e_output_files)
    #reversed_fork_rel = get_reversed_fork_relations(s2e_output_files)
    #prettyprint_reversed_fork_relations(reversed_fork_rel)

    derived_states = get_derived_states(fork_rel, 27545)
    print(derived_states)
    



