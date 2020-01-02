#!/usr/bin/env python

import argparse
import os

from time import sleep

from scapy.all import rdpcap, TCP


SYN = 0x02
RST = 0x04
ACK = 0x10
FIN = 0x01


BAD_KEYWORD = 'ultrasurf'


parser = argparse.ArgumentParser(description='Replay packet traces for tracing with PIN.')
parser.add_argument('-P', '--pcap-dir', default='./succ_pcaps', type=str, help='Folder of pcaps')
#parser.add_argument('-S', '--system', default='all', type=str, help='Only enable strategies that are known to work against specific DPI')
args = parser.parse_args()


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

i = 0
for fname in os.listdir(args.pcap_dir):
    i += 1
    print("[%d] Replaying %s..." % (i, fname))
    os.system("echo '%s' > fname" % fname)
    fpath = os.path.join(args.pcap_dir, fname)
    packets = rdpcap(fpath)
    client_port = find_client_port(packets)
    if not client_port:
        print("Cannot find client port.")
        continue

    # filter packets
    os.system("tcpdump -r %s -w tmp.pcap tcp port %d" % (fpath, client_port))
    packets = rdpcap('tmp.pcap')

    # find the index of the data packet with sensitive keyword
    sdata_idx = 0
    for packet in packets:
        sdata_idx += 1
        if packet[TCP].payload and BAD_KEYWORD in packet[TCP].payload.load:
            break
    if not sdata_idx:
        print("Cannot find data packet with sensitive keyword.")
        continue
    print("SData Idx: %d" % sdata_idx)

    os.system("tcpreplay -i lo -t -L %d tmp.pcap" % sdata_idx)

    sleep(2)




