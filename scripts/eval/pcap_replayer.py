#!/usr/bin/env python
# BEWARE: This scripts only read packets from packet dump, you need to send them yourself.

import glob
import os
import random
import socket
import struct
import sys

from time import sleep

#from scapy.all import rdpcap, TCP, IP, in4_chksum, TCPOptionsField, orb, TCPOptions
from scapy.all import rdpcap, Ether, TCP, IP, Raw, in4_chksum, sr, sr1, send, conf, L3RawSocket, hexdump

# a hotfix to scapy TCP answer function
def myanswers(self, other):
    if not isinstance(other, TCP):
        return 0
    # RST packets don't get answers
    if other.flags.R:
        return 0
    # We do not support the four-way handshakes with the SYN+ACK
    # answer split in two packets (one ACK and one SYN): in that
    # case the ACK will be seen as an answer, but not the SYN.
    if self.flags.S:
        # SYN packets without ACK are not answers
        if not self.flags.A:
            return 0
        # SYN+ACK packets answer SYN packets
        if not other.flags.S:
            return 0
    if conf.checkIPsrc:
        if not ((self.sport == other.dport) and
                (self.dport == other.sport)):
            return 0
    # Do not check ack value for SYN packets without ACK
    #if not (other.flags.S and not other.flags.A) \
    #   and abs(other.ack - self.seq) > 2:
    #    return 0
    # Do not check ack value for RST packets without ACK
    if self.flags.R and not self.flags.A:
        return 1
    #if abs(other.seq - self.ack) > 2 + len(other.payload):
    #    return 0
    return 1

TCP.answers = myanswers

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

conf.L3socket=L3RawSocket

SYN = 0x02
RST = 0x04
ACK = 0x10
FIN = 0x01

MOD32 = 2**32

HTTP_REQ = "GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAultrasurf HTTP/1.1\r\nHost: local_test_server\r\n\r\n"

SERVER_PORT = 80

server_ip = '47.105.66.190'

client_port = random.randint(10000, 40000)

import argparse
parser = argparse.ArgumentParser(description='Read packets from a packet dump file and replay the client packets.')
parser.add_argument('pcap_file', type=str, help='Packet dump file.')
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
            if packet[TCP].dport == SERVER_PORT:
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
            elif packet[TCP].sport == SERVER_PORT:
                if packet[TCP].flags & (SYN | ACK) == SYN | ACK:
                    # SYN/ACK packet
                    #print("SYN/ACK recved.")
                    if client_ports.get(packet[TCP].dport) == 1:
                        client_ports[packet[TCP].dport] = 2
        else:
            print('Non-TCP packet?!')
            print(packet.summary())

    return 0

# find server ISN using SYN/ACK packet
def find_server_isn(packets, client_port):
    for packet in packets:
        if TCP in packet:
            if packet[TCP].dport == client_port:
                if packet[TCP].flags & (SYN | ACK) == SYN | ACK:
                    # SYN/ACK packet
                    return packet[TCP].seq


packets = rdpcap(args.pcap_file)
orig_client_port = find_client_port(packets)
if not orig_client_port:
    print("Cannot find client port.")
    sys.exit(-1)

# filter packets with client port, and replace client port
packets_filtered = []
for packet in packets:
    if TCP in packet:
        if packet[TCP].sport == orig_client_port:
            pkt = packet[IP]
            del pkt[IP].src
            pkt[IP].dst = server_ip
            # clear IP checksum, need to recompute later
            del pkt[IP].chksum
            # update TCP layer will recompute packet length
            pkt[TCP].sport = client_port
            if packet[TCP].chksum != 0xffff:
                # need to recompute TCP checksum later
                del pkt[TCP].chksum
            if len(pkt) < pkt[IP].len:
                for x in range(pkt[IP].len - len(pkt)):
                    pkt[TCP].options.append(('EOL', None))
            packets_filtered.append(pkt)
        elif packet[TCP].dport == orig_client_port:
            pkt = packet[IP]
            del pkt[IP].dst
            pkt[IP].src = server_ip
            pkt[TCP].dport = client_port
            packets_filtered.append(pkt)
    else:
        print('Non-TCP packet?!')
        print(packet.summary())
packets = packets_filtered

orig_server_isn = find_server_isn(packets, client_port)
if not orig_server_isn:
    print("Cannot find server ISN.")
    sys.exit(-1)

# get the i-th client packet, index starts from 1
def get_client_packet(index):
    i = 0
    for packet in packets:
        if packet[TCP].sport == client_port:
            i += 1
            if i == index:
                return packet


client_isn = 0
server_isn = 0
server_seq = 0
server_ack = 0

def update_server_seq_n_ack(ans):
    global server_seq, server_ack
    for _, packet in ans:
        # update server seq
        end_seq = add(packet[TCP].seq, len(packet[TCP].payload))
        if before(server_seq, end_seq):
            server_seq = end_seq
        # update server ack
        if packet[TCP].flags & ACK == ACK:
            if before(server_ack, packet[TCP].ack):
                server_ack = packet[TCP].ack


####################
# User-edited Code #
####################

syn_pkt = get_client_packet(1)
syn_pkt[TCP].sport = client_port

#hexdump(syn_pkt)
reply_pkt = sr1(syn_pkt, timeout=2, verbose=False) 
print("Sent 1st packet...")

if reply_pkt:
    #hexdump(reply_pkt)
    if TCP in reply_pkt and reply_pkt['TCP'].flags & (SYN | ACK) == SYN | ACK:
        print("Received SYN/ACK packet...")
        # update isn_server with received reply_pkt
        server_isn = reply_pkt['TCP'].seq
        server_seq = add(server_isn, 1)
        server_ack = reply_pkt['TCP'].ack
    else:
        print("Received non SYN/ACK packet.")
        sys.exit(-1)
else:
    print("No SYN/ACK packet received.")
    sys.exit(-1)

pkt2 = get_client_packet(2)
pkt2[IP].dst = server_ip
pkt2[TCP].sport = client_port
pkt2[TCP].ack = add(sub(pkt2[TCP].ack, orig_server_isn), server_isn)

#hexdump(pkt2)
ans, unans = sr(pkt2, timeout=2)
print("Sent 2nd packet...")
update_server_seq_n_ack(ans)

"""
pkt3 = get_client_packet(3)
pkt3[IP].dst = server_ip
pkt3[TCP].sport = client_port
pkt3[TCP].ack = add(sub(pkt3[TCP].ack, orig_server_isn), server_isn)

#hexdump(pkt3)
ans, unans = sr(pkt3, timeout=2)
print("Sent 3rd packet...")
update_server_seq_n_ack(ans)
"""

#####################
# Follow-up packets #
#####################

ack_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=server_ack, ack=server_seq)

#hexdump(ack_pkt)
send(ack_pkt)
print("Sent ACK packet...")

payload = HTTP_REQ
data_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=server_ack, ack=server_seq)/Raw(load=payload)

#hexdump(data_pkt)
send(data_pkt)
print("Sent Data packet...")

