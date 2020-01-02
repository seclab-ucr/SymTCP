#!/usr/bin/env python

import os
import glob

from scapy.all import rdpcap, TCP

PCAP_DIR = "./succ_pcaps"

SYN = 0x02
RST = 0x04
ACK = 0x10
FIN = 0x01

client_isn = 0
client_seq = 0

results = {}

result_file = 'results'

f = open(result_file, 'r')
for line in f:
    entry = eval(line)
    results[entry['state_id']] = entry
f.close()

succs = {}

succ_list_file = 'gfw_succ_list'

f = open(succ_list_file, 'r')
for line in f:
    state_id, packet_num, tcp_flags, kind = line.rstrip().split(',')
    packet_num = int(packet_num)
    if state_id not in succs:
        succs[state_id] = []
    succs[state_id].append((state_id, packet_num, tcp_flags, kind))
f.close()


same_seq_count = 0
poss_pkt_loss_count = 0

files = glob.glob(PCAP_DIR + "/packet_dump_*.pcap")
for fname in files:
    fname2 = os.path.basename(fname)
    parts = fname2.split('_')
    if parts[3] == 'c':
        state_id = '_'.join(parts[2:6])
        if len(parts) == 11:
            tcp_flags = parts[-2]
        else:
            tcp_flags = 'UNCONSTRAINED'
    else:
        state_id = parts[2]
        if len(parts) == 8:
            tcp_flags = parts[-2]
        else:
            tcp_flags = 'UNCONSTRAINED'
    packet_num = int(parts[-1].split('.')[0])
    #print(state_id)
    #print(packet_num)
    #print(tcp_flags)

    packets = rdpcap(fname)
    if len(packets) == 0:
        #print("Empty pcap!")
        continue
    i = 0
    for packet in packets:
        #packet.show()
        if TCP in packet:
            if packet[TCP].dport == 80:
                # client -> server
                i += 1
                if i == 1:
                    if packet[TCP].flags & SYN:
                        client_isn = packet[TCP].seq
                    else:
                        print("%s: First packet is not SYN! %s" % (fname, packet[TCP].flags))
                        break
                elif i == 2:
                    if packet[TCP].flags != last_packet[TCP].flags and packet[TCP].seq == last_packet[TCP].seq:
                        print(fname2)
                        same_seq_count +=1
                        found = False
                        for succ in succs[state_id]:
                            #print(succ)
                            if succ[2] == tcp_flags:
                                if succ[1] == 2 and succ[3] == 'Evasion':
                                    print("%s: Second packet SEQ == ISN! Found Succ: %s" % (fname2, succ))
                                    found = True
                                    #os.remove(fname)
                                    break
                        if not found:
                            print(results[state_id]['results'])
                            # passibly due to packet loss
                            for tcp_flags in results[state_id]['results'][i]:
                                res = results[state_id]['results'][i][tcp_flags]
                                if isinstance(res, dict):
                                    if res['gfw'] == False:
                                        poss_pkt_loss_count += 1
                                        break

                        #raw_input("Press ENTER to continue...")
                        #print("%s: Second packet SEQ == ISN!" % (fname))
                        break
                last_packet = packet


print("Same SEQ count: %d" % same_seq_count)
print("Possible packet loss count: %d" % poss_pkt_loss_count)





