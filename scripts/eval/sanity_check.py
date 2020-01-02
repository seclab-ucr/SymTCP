#!/usr/bin/env python

import os
import sys
import traceback

from scapy.all import rdpcap, TCP, IP


SYN = 0x02
RST = 0x04
ACK = 0x10
FIN = 0x01

SERVER_PORT = 80


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

def filter_packets(packets, client_port):
    packets_filtered = []
    for packet in packets:
        if TCP in packet:
            if packet[TCP].sport == client_port or packet[TCP].dport == client_port:
                packets_filtered.append(packet)
    return packets_filtered

def check(packets):
    client_port = find_client_port(packets)
    if not client_port:
        #print("Cannot find client port.")
        return -1

    packets = filter_packets(packets, client_port)
    ttls = []
    for packet in packets:
        if packet[TCP].flags & (SYN | ACK) == SYN | ACK:
            if packet[IP].ttl not in ttls:
                ttls.append(packet[IP].ttl)

    if len(ttls) != 1:
        print("Warning! TTLs: %s" % ttls)
        return -1

    return 0


if __name__ == "__main__":
    pcaps_dir = sys.argv[1]

    for fname in os.listdir(pcaps_dir):
        if not fname.endswith(".pcap"):
            continue
        fpath = os.path.join(pcaps_dir, fname)
        try:
            packets = rdpcap(fpath)
            ret = check(packets)
            if ret < 0:
                os.remove(fpath)
        except Exception:
            print(fpath)
            traceback.print_exc()


