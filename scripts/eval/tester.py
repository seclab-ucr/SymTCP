#!/usr/bin/env python

import sys
import random

from time import sleep

from scapy.all import IP, TCP, Raw, sr1, send, conf, L3RawSocket

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

conf.L3socket=L3RawSocket

SYN = 0x02
RST = 0x04
ACK = 0x10
FIN = 0x01

HTTP_REQ = "GET /AAAAAAAAAAAAAAAAAAAAAAAA#ultrasurf# HTTP/1.1\r\nHost: local_test_server\r\n\r\n"
GOOD_HTTP_REQ = "GET /AAAAAAAAAAAAAAAAAAAAAAAA HTTP/1.1\r\nHost: local_test_server\r\n\r\n"


server_ip = '127.0.0.1'
server_ip = '169.235.26.60'
server_ip = '183.131.178.75'
server_ip = '139.129.13.125'

SERVER_PORT = 80

client_port = random.randint(10000, 40000)

# client initial sequence number
client_isn = random.getrandbits(32)
# server initial sequence number
server_isn = 0

#syn_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='S', seq=client_isn, options=[('Timestamp', (0x80000000, 0)), ('NOP', None), ('NOP', None)])/Raw(load='GET /AAA')
syn_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='S', seq=client_isn)
syn_pkt['IP'].ttl = 163 # to bypass the iptables rule

#hexdump(syn_pkt)
reply_pkt = sr1(syn_pkt, timeout=3) 
print("Sent SYN packet...")
client_seq = client_isn + 1

if reply_pkt:
    #hexdump(reply_pkt)
    if TCP in reply_pkt and reply_pkt['TCP'].flags & (SYN | ACK) == SYN | ACK:
        print("Received SYN/ACK packet...")
        # update isn_server with received reply_pkt
        server_isn = reply_pkt['TCP'].seq
        server_seq = server_isn + 1
    else:
        print("Received non SYN/ACK packet.")
        sys.exit(-1)
else:
    print("No SYN/ACK packet received.")
    sys.exit(-1)

#ack_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_seq, ack=server_seq)/Raw(load='AAAAAAAA')
ack_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_seq, ack=server_seq)
ack_pkt['IP'].ttl = 163 # to bypass the iptables rule

#hexdump(ack_pkt)
send(ack_pkt) 
print("Sent ACK packet...")

sleep(1)

# INSERTION PACKET!!!!!!!!!
#ins_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='R', seq=client_seq, ack=server_seq, options=[(19, '\xff'*16)])
ins_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='R', seq=client_seq, ack=server_seq, chksum=0xffff)
#ins_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='R', seq=client_seq, ack=server_seq)
#ins_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='F', seq=client_seq, ack=server_seq, options=[('NOP', None), ('NOP', None), ('Timestamp', (0xffeffdf8, 0))])/Raw(load='GET ')
ins_pkt['IP'].ttl = 163 # to bypass the iptables rule

#hexdump(ins_pkt)
send(ins_pkt)
print("Sent Insertion packet...")

sleep(1)

#payload = 'ultrasurf HTTP/1.1\r\nHost: local_test_server\r\n\r\n'
payload = HTTP_REQ
#payload = GOOD_HTTP_REQ
data_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_seq, ack=server_seq)/Raw(load=payload)
#data_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=0, ack=server_seq)/Raw(load=payload)
data_pkt['IP'].ttl = 163 # to bypass the iptables rule

#hexdump(data_pkt)
send(data_pkt)
print("Sent Data packet...")


