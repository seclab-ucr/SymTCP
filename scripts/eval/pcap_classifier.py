#!/usr/bin/env python

import os
import glob
import socket
import struct

#from scapy.all import rdpcap, TCP, IP, in4_chksum, TCPOptionsField, orb, TCPOptions
from scapy.all import rdpcap, TCP, IP, in4_chksum

"""
def mym2i(self, pkt, x):
    import pdb
    pdb.set_trace()
    opt = []
    while x:
        onum = orb(x[0])
        if onum == 0:
            opt.append(("EOL",None))
            x=x[1:]
            break
        if onum == 1:
            opt.append(("NOP",None))
            x=x[1:]
            continue
        if len(x) < 2:
            if onum in TCPOptions[0]:
                oname, ofmt = TCPOptions[0][onum]
                opt.append((oname, ''))
            else:
                opt.append((onum, ''))
            x=x[1:]
            continue
        olen = orb(x[1])
        if olen < 2:
            warning("Malformed TCP option (announced length is %i)" % olen)
            olen = 2
        oval = x[2:olen]
        if onum in TCPOptions[0]:
            oname, ofmt = TCPOptions[0][onum]
            if onum == 5: #SAck
                ofmt += "%iI" % (len(oval)//4)
            if ofmt and struct.calcsize(ofmt) == len(oval):
                oval = struct.unpack(ofmt, oval)
                if len(oval) == 1:
                    oval = oval[0]
            opt.append((oname, oval))
        else:
            opt.append((onum, oval))
        x = x[olen:]
    return opt

TCPOptionsField.m2i = mym2i
"""

SYN = 0x02
RST = 0x04
ACK = 0x10
FIN = 0x01

MOD32 = 2**32

WINDOW_SIZE = 65535


import argparse
parser = argparse.ArgumentParser(description='Classify the successful test cases into different strategies.')
parser.add_argument('-P', '--pcap-dir', default='./succ_pcaps', type=str, help='Folder of successful pcaps')
parser.add_argument('-S', '--system', default='all', type=str, help='Only enable strategies that are known to work against specific DPI')
parser.add_argument('--rm', default=False, action='store_true', help='Remove pcaps belong to known strategies')
args = parser.parse_args()

def add(a, b):
    return (a + b) % MOD32

def sub(a, b):
	return (a - b) % MOD32

def before(a, b):
    if abs(a - b) > 2**31:
        if a < b:
            return False
        else:
            return True
    else:
        if a < b:
            return True
        else:
            return False

def after(a, b):
    return before(b, a)

# copied from Linux kernel TCP code
def tcp_in_window(seq, end_seq, s_win, e_win):
    if seq == s_win:
        return True
    if after(end_seq, s_win) and before(seq, e_win):
        return True
    return seq == e_win and seq == end_seq

def has_tcp_md5_opt(packet):
    #print(packet[TCP].options)
    for opt in packet[TCP].options:
        if opt[0] == 19:
            return True
    return False

# find client port using 3-way handshake
def find_client_port(packets):
    client_ports = {}
    for packet in packets:
        if TCP in packet:
            if packet[TCP].dport == 80:
                if packet[TCP].flags & SYN == SYN:
                    # SYN packet
                    #print("SYN recved.")
                    if packet[TCP].sport not in client_ports:
                        client_ports[packet[TCP].sport] = 1
                if packet[TCP].flags & ACK == ACK:
                    # ACK packet
                    #print("ACK recved.")
                    if client_ports.get(packet[TCP].sport) == 2:
                        client_ports[packet[TCP].sport] = 3
                        # found
                        return packet[TCP].sport
            elif packet[TCP].sport == 80:
                if packet[TCP].flags & (SYN | ACK) == SYN | ACK:
                    # SYN/ACK packet
                    #print("SYN/ACK recved.")
                    if client_ports.get(packet[TCP].dport) == 1:
                        client_ports[packet[TCP].dport] = 2
        else:
            print('Non-TCP packet?!')
            print(packet.summary())

    return 0

def is_seq_le_isn(packets):
    client_port = find_client_port(packets)
    if not client_port:
        return False
    isn = 0
    i = 0
    for packet in packets:
        if TCP in packet and packet[TCP].sport == client_port:
            # TCP: client -> server
            i += 1
            if i == 1:
                if packet[TCP].flags & SYN != SYN:
                    # first c->s packet has to be SYN
                    return False
                isn = packet[TCP].seq
            if i == 2:
                if packet[TCP].flags & ACK == ACK:
                    seq = packet[TCP].seq
                    left_boundary = sub(isn, 1024)
                    if seq == isn or before(seq, isn) and after(seq, left_boundary):
                        return True
            if i == 3:
                if packet[TCP].flags & ACK == ACK:
                    seq = packet[TCP].seq
                    left_boundary = sub(isn, 1024)
                    if seq == isn or before(seq, isn) and after(seq, left_boundary):
                        return True

    return False

def is_rst_challenge_ack(packets):
    client_port = find_client_port(packets)
    if not client_port:
        return False

    i = 0
    server_ack_recved = False
    server_ack = 0
    for packet in packets:
        if TCP in packet:
            if packet[TCP].sport == client_port:
                i += 1
                if i == 3:
                    if packet[TCP].flags & RST == RST:
                        seq = packet[TCP].seq
                        if server_ack_recved:
                            right_boundary = add(server_ack, 65535)
                            if seq != server_ack and not before(seq, server_ack) and before(seq, right_boundary):
                                return True
            elif packet[TCP].dport == client_port:
                server_ack_recved = True
                server_ack = packet[TCP].ack 

    return False

def is_small_segments(packets):
    client_port = find_client_port(packets)
    if not client_port:
        return False

    i = 0
    server_isn_recved = False
    server_isn = 0
    server_ack_recved = False
    server_ack = 0
    small_seg_sent = False
    client_seq = 0
    for packet in packets:
        if TCP in packet:
            if packet[TCP].sport == client_port:
                i += 1
                if i == 2:
                    if packet[TCP].flags & ACK == ACK:
                        if server_isn_recved:
                            if len(packet[TCP].payload) <= 8 and len(packet[TCP].payload) > 0:
                                small_seg_sent = True
                                small_seg_size = len(packet[TCP].payload)
                                after_small_seg_seq = add(packet[TCP].seq, small_seg_size)
                                #print("Small segment sent, size: %d" % small_seg_size)
            elif packet[TCP].dport == client_port:
                if packet[TCP].flags & (SYN | ACK) == SYN | ACK:
                    server_isn_recved = True
                    server_isn = packet[TCP].seq
                if packet[TCP].flags & ACK == ACK:
                    server_ack_recved = True
                    server_ack = packet[TCP].ack 
                    if small_seg_sent and server_ack == after_small_seg_seq:
                        #print("Small segment acked by server.")
                        return True

    return False

def is_rst_fin_bad_checksum(packets):
    client_port = find_client_port(packets)
    if not client_port:
        return False

    i = 0
    for packet in packets:
        if TCP in packet:
            if packet[TCP].sport == client_port:
                i += 1
                if i == 2:
                    if packet[TCP].flags & (RST | ACK) == RST | ACK \
                            or packet[TCP].flags & (FIN | ACK) == FIN:
                        verify_chksum = in4_chksum(socket.IPPROTO_TCP, packet[IP], str(packet[TCP]))
                        if verify_chksum != 0:
                            return True
                if i == 3:
                    if packet[TCP].flags & (RST | ACK) == RST | ACK \
                            or packet[TCP].flags & (FIN | ACK) in (FIN, FIN | ACK):
                        verify_chksum = in4_chksum(socket.IPPROTO_TCP, packet[IP], str(packet[TCP]))
                        if verify_chksum != 0:
                            return True

    return False

def is_rst_fin_md5(packets):
    client_port = find_client_port(packets)
    if not client_port:
        return False

    i = 0
    for packet in packets:
        if TCP in packet:
            if packet[TCP].sport == client_port:
                i += 1
                if i == 2:
                    if packet[TCP].flags & (RST | ACK) == RST | ACK \
                            or packet[TCP].flags & (FIN | ACK) == FIN:
                        if has_tcp_md5_opt(packet):
                            return True
                if i == 3:
                    if packet[TCP].flags & (RST | ACK) == RST | ACK \
                            or packet[TCP].flags & (FIN | ACK) in (FIN, FIN | ACK):
                        if has_tcp_md5_opt(packet):
                            return True

    return False

def is_fin_with_data(packets):
    client_port = find_client_port(packets)
    if not client_port:
        return False

    i = 0
    for packet in packets:
        if TCP in packet:
            if packet[TCP].sport == client_port:
                i += 1
                if i == 2:
                    if packet[TCP].flags & (FIN | ACK) == FIN:
                        if packet[TCP].dataofs * 4 < packet[IP].len - 20:
                            return True
                if i == 3:
                    if packet[TCP].flags & (FIN | ACK) == FIN:
                        if packet[TCP].dataofs * 4 < packet[IP].len - 20:
                            return True

    return False

def is_fin_without_data(packets):
    client_port = find_client_port(packets)
    if not client_port:
        return False

    data_sent = False
    i = 0
    for packet in packets:
        if TCP in packet:
            if packet[TCP].sport == client_port:
                i += 1
                if i == 2:
                    if packet[TCP].flags & ACK == ACK:
                        if packet[TCP].dataofs * 4 == packet[IP].len - 20:
                            data_sent = True
                if i == 3:
                    if data_sent:
                        if packet[TCP].flags & (FIN | ACK) == FIN:
                            if packet[TCP].dataofs * 4 == packet[IP].len - 20:
                                return True

    return False

def is_snort_fin_ack(packets):
    client_port = find_client_port(packets)
    if not client_port:
        return False

    i = 0
    client_isn = 0
    server_isn_recved = False
    server_isn = 0
    fin_ack_ok = False
    for packet in packets:
        if TCP in packet:
            if packet[TCP].sport == client_port:
                i += 1
                if i == 1:
                    client_isn = packet[TCP].seq
                if i == 2:
                    if packet[TCP].flags & (FIN | ACK) == FIN | ACK \
                            and packet[TCP].ack == add(server_isn, 1) \
                            and not before(packet[TCP].seq, client_isn + 2):
                        fin_ack_ok = True
                if i == 3:
                    if fin_ack_ok and packet[TCP].flags & ACK == ACK \
                            and packet[TCP].seq == add(client_isn, 1) \
                            and packet[TCP].ack == add(server_isn, 1):
                        return True
            elif packet[TCP].dport == client_port:
                if packet[TCP].flags & (SYN | ACK) == SYN | ACK:
                    server_isn_recved = True
                    server_isn = packet[TCP].seq

    return False

def is_data_without_ack_flag(packets):
    client_port = find_client_port(packets)
    if not client_port:
        return False

    i = 0
    client_isn = 0
    server_isn_recved = False
    server_isn = 0
    server_ack_recved = False
    server_ack = 0
    for packet in packets:
        if TCP in packet:
            if packet[TCP].sport == client_port:
                i += 1
                if i == 1:
                    client_isn = packet[TCP].seq
                if i == 2:
                    if packet[TCP].flags & ACK == 0 \
                            and server_ack_recved and packet[TCP].seq == server_ack \
                            and packet[TCP].ack == add(server_isn, 1) \
                            and packet[TCP].dataofs * 4 < packet[IP].len - 20:
                        return True
                if i == 3:
                    if packet[TCP].flags & ACK == 0 \
                            and server_ack_recved and packet[TCP].seq == server_ack \
                            and packet[TCP].ack == add(server_isn, 1) \
                            and packet[TCP].dataofs * 4 < packet[IP].len - 20:
                        return True
            elif packet[TCP].dport == client_port:
                if packet[TCP].flags & ACK == ACK:
                    server_ack_recved = True
                    server_ack = packet[TCP].ack
                if packet[TCP].flags & (SYN | ACK) == SYN | ACK:
                    server_isn_recved = True
                    server_isn = packet[TCP].seq

    return False

def is_snort_ooo_data(packets):
    client_port = find_client_port(packets)
    if not client_port:
        return False

    i = 0
    server_ack_recved = False
    server_ack = 0
    gap_seqs = []
    for packet in packets:
        if TCP in packet:
            if packet[TCP].sport == client_port:
                i += 1
                if server_ack_recved:
                    if packet[TCP].flags & (SYN | ACK | FIN | RST) == ACK \
                            and packet[TCP].seq != server_ack \
                            and len(packet[TCP].payload) > 0 \
                            and tcp_in_window(packet[TCP].seq, add(packet[TCP].seq, len(packet[TCP].payload)), server_ack, add(server_ack, WINDOW_SIZE)):
                        # there is a gap
                        gap_seqs.append(packet[TCP].seq)
            elif packet[TCP].dport == client_port:
                if packet[TCP].flags & ACK == ACK:
                    server_ack_recved = True
                    server_ack = packet[TCP].ack
                    gap_seqs_new = []
                    for gap_seq in gap_seqs:
                        if after(gap_seq, server_ack):
                            gap_seqs_new.append(gap_seq)
                    gap_seqs = gap_seqs_new

    if gap_seqs:
        return True
    return False


STRATEGIES = {
    1: { 'name': 'seq_lte_isn', 'f': is_seq_le_isn, 'str': 'Data packet with SEQ num less than or equal to ISN. (Evasion)' },
    2: { 'name': 'small_segments', 'f': is_small_segments, 'str': 'Small Segments (less or equal than 8-byte). (Evasion)' },
    3: { 'name': 'rst_challenge_ack', 'f': is_rst_challenge_ack, 'str': 'RST Challenge ACK. (Insertion)' },
    4: { 'name': 'rst_fin_bad_check_sum', 'f': is_rst_fin_bad_checksum, 'str': 'RST or FIN packet with bad checksum in SYN_RECV or ESTABLISHED state. (Insertion)' },
    5: { 'name': 'rst_fin_md5', 'f': is_rst_fin_md5, 'str': 'RST or FIN packet with MD5 in SYN_RECV or ESTABLISHED state. (Insertion)' },
    6: { 'name': 'fin_with_data', 'f': is_fin_with_data, 'str': 'FIN packet with data. (Insertion)' },
    7: { 'name': 'fin_without_data', 'f': is_fin_without_data, 'str': 'FIN packet without data (requires data already in receive buffer, in-order or out-of-order). (Insertion)' },
    8: { 'name': 'snort_fin_ack', 'f': is_snort_fin_ack, 'str': 'FIN in SYN_RECV state, then ACK. (Insertion)' },
    9: { 'name': 'data_without_ack_flag', 'f': is_data_without_ack_flag, 'str': 'Data packet without ACK flag. (Insertion)' },
    10: { 'name': 'snort_ooo_data', 'f': is_snort_ooo_data, 'str': 'Snort cannot properly handler out-of-order data. If there is a gap in the data, it will not even process the data on the left of the gap. (Evasion)' },
}

SYSTEMS = {
    'gfw': [1, 2, 3, 4, 5, 6, 7],
    'snort': [8, 9, 10],
    'bro': [9],
}


def classify(packets):
    for sid, val in STRATEGIES.iteritems():
        if args.system == 'all' or sid in SYSTEMS[args.system]:
            if val['f'](packets):
                return sid
    return 0


stats = {}

files = glob.glob(args.pcap_dir + "/packet_dump_*.pcap")
for fname in files:
    packets = rdpcap(fname)
    if len(packets) == 0:
        #print("Empty pcap!")
        continue

    cls = classify(packets)
    if cls not in stats:
        stats[cls] = 0
    stats[cls] += 1

    if cls:
        #print(fname)
        if args.rm:
            os.remove(fname)


for k, v in stats.iteritems():
    print("%d. %s: %d" % (k, STRATEGIES.get(k, {'name': 'Unknown'})['name'], v))



