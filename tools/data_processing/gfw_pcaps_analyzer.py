import argparse
import os
from collections import Counter
from scapy.all import *
from scapy_http.http import HTTPResponse

SYN = 0x02
RST = 0x04
ACK = 0x10

TCP_FLAGS = {'SYN', 'RST', 'ACK', 'FIN', 'RSTACK', 'FINACK'}

parser = argparse.ArgumentParser(description='Anaylze GFW pcap files')
parser.add_argument('-PD', '--pcaps-dir', type=str, help='dir that contains pcap files')
parser.add_argument('-TC', '--test-cases', type=str)
parser.add_argument('-DR', '--dump-res', action='store_true')
parser.add_argument('-DD', '--dump-debug', action='store_true')
parser.add_argument('-DE', '--dump-examples', action='store_true')
parser.add_argument('-DEP', '--dump-empty-pcaps', action='store_true')
parser.add_argument('-DBR', '--dump-bypass-res', action='store_true')
parser.add_argument('-D', '--debug', action='store_true')
args = parser.parse_args()

pcap_dir = args.pcaps_dir + '/'

rst_id_ip_list = []
server_recived_lst = []
gfw_bypasses = []
gfw_bypasses_ids = []
gfw_bypasses_ids_flags = []
gfw_bypasses_ids_flags_dict = {}
id_to_filename = {}
empty_pcap_set = set()

cnt = 0
START_FROM = 0
no_tcp_count = 0
empty_pcap_cnt = 0

def check_gfw_rst(packets, filename):
    global no_tcp_count
    rst_ack_cnt = 0
    recved_gfw_type1_rst, recved_gfw_type2_rst = False, False
    for packet in packets:
        if not packet.haslayer(TCP):
            if args.debug:
                print("[ERROR] No TCP layer detected: %s" % filename)
            no_tcp_count += 1
            continue
        if packet['TCP'].flags == RST:
            if packet['IP'].flags == 0 and packet['TCP'].window != 0:
                recved_gfw_type1_rst = True
        elif packet['TCP'].flags == RST | ACK:
            rst_ack_cnt += 1
    # since we only send one data packet, if we received more than 1 RST/ACK, then they should be from the GFW
    if rst_ack_cnt > 1:
        recved_gfw_type2_rst = True
    return recved_gfw_type1_rst or recved_gfw_type2_rst

def check_server_response(packets, ip):
    for packet in packets:
        if packet.haslayer(HTTPResponse):
            return True
    return False

def dump_per_dp_bypass_stats(fname, bypasses_dict, example_set):
    per_dp_dict = {}
    total_example_count_w_flags = 0
    total_example_count_wo_flags = 0
    for state_id, example in example_set.items():
        drop_point = eval(example[:-1])['dp']
        if state_id in bypasses_dict:
            total_example_count_wo_flags += 1
            flags = bypasses_dict[state_id]
            if drop_point not in per_dp_dict:
                per_dp_dict[drop_point] = {}
                for f in flags:
                    per_dp_dict[drop_point][f] = 1
                    total_example_count_w_flags += 1
            else:
                for f in flags:
                    if f not in per_dp_dict[drop_point]:
                        per_dp_dict[drop_point][f] = 1
                        total_example_count_w_flags += 1
                    else:
                        per_dp_dict[drop_point][f] += 1
                        total_example_count_w_flags += 1
    print("Total count of success examples w/ flags: %d" % total_example_count_w_flags)
    print("Total count of success examples wo/ flags: %d" % total_example_count_wo_flags)
    with open(fname, 'w') as fout:
        for dp, flags_dict in per_dp_dict.items():
            fout.write(dp + '\n')
            for f, count in flags_dict.items():
                fout.write(','.join([f, str(count)]) + '\n')

def dump_success_dp_stats(fname, bypasses, example_set):
    success_dp_counts = Counter()
    total_dp_counts = Counter()
    for state_id, example in example_set.items():
        drop_point = eval(example[:-1])['dp']
        if state_id in set(bypasses):
            success_dp_counts[drop_point] += 1
        total_dp_counts[drop_point] += 1

    print("Sum:", sum(success_dp_counts.values()))
    with open(fname, 'w') as fout:
        for key, value in total_dp_counts.items():
            if key in success_dp_counts:
                record = ','.join([key, str(value), str(success_dp_counts[key])])
            else:
                record = ','.join([key, str(value), str(0)])
            print(record)
            record += '\n'
            fout.write(record)

if not args.pcaps_dir:
    print("No pcap dir supplied, quitting...")
    exit

total_count_of_state_id = set()
for filename in os.listdir(pcap_dir):
    if cnt < START_FROM:
        continue
    cnt += 1
    try:
        packets = rdpcap(pcap_dir + filename)
    except Scapy_Exception:
        print("Bad pcap...")
        continue
    
    # Parse possible filename formats
    filename = '.'.join(filename.split('.')[:-1])
    underline_splits = filename.split('_')
    
    if len(underline_splits) == 11:
        id_lst = underline_splits[2:6]
        id_lst.append(underline_splits[-2])
        id = '_'.join(id_lst)
        ip = underline_splits[-5]
    elif len(underline_splits) == 10:
        id_lst = underline_splits[2:6]
        id = '_'.join(id_lst)
        ip = underline_splits[-4]
    elif len(underline_splits) == 8:
        id = '_'.join([underline_splits[2], underline_splits[-2]])
        ip = underline_splits[-5]
    elif len(underline_splits) == 7:
        id = underline_splits[2]
        ip = underline_splits[-4]
    else:
        print("WTF???")
        exit()
    
    if id.split('_')[-1] in TCP_FLAGS:
        total_count_of_state_id.add('_'.join(id.split('_')[:-1]))
    else:
        total_count_of_state_id.add(id)

    id_ip = '#'.join([id, ip])
    id_to_filename[id_ip] = filename + '\n'
    
    if len(packets) == 0:
        if args.debug:
            print("[Error] Empty pcap detected!")
        empty_pcap_set.add(id)
        empty_pcap_cnt += 1
        continue

    if check_server_response(packets, ip):
        server_recived_lst.append(id_ip)
    if check_gfw_rst(packets, filename):
        rst_id_ip_list.append(id_ip)

print("Count of non-TCP packets:", no_tcp_count)
print("Count of empty pcaps:", empty_pcap_cnt)
print("Count of unique state ids:", len(total_count_of_state_id))

server_recived_lst, rst_id_ip_list = list(set(server_recived_lst)), list(set(rst_id_ip_list))

for case in server_recived_lst:
    if case not in set(rst_id_ip_list):
        id, ip = case.split('#')
        if id.split('_')[-1] in TCP_FLAGS:
            state_id = '_'.join(id.split('_')[:-1])
            flags = id.split('_')[-1]
        else:
            state_id = id
            flags = "Unconstrained"

        if state_id not in gfw_bypasses_ids_flags_dict:
            gfw_bypasses_ids_flags_dict[state_id] = [flags]
        else:
            gfw_bypasses_ids_flags_dict[state_id].append(flags)

        gfw_bypasses_ids.append(state_id)
        gfw_bypasses_ids_flags.append(id)
        gfw_bypasses.append(id + '\n')

print("Success (id)", len(set(gfw_bypasses_ids)))
print("Success (id w/ flags)", len(set(gfw_bypasses_ids_flags)))
print("Num of server_recived_lst:", len(server_recived_lst))
print("Num of rst_id_ip_list:", len(rst_id_ip_list))

if args.test_cases:
    example_set = {}
    with open(args.test_cases, 'r') as fin:
        data = fin.readlines()
    for d in data:
        state_id = eval(d[:-1])['state_id']
        example_set[state_id] = d

if args.dump_bypass_res:
    dump_per_dp_bypass_stats('gfw_per_dp_per_flag_stats.txt', gfw_bypasses_ids_flags_dict, example_set)
    dump_success_dp_stats('gfw_per_dp_stats.txt', gfw_bypasses_ids, example_set)

if args.dump_res:
    with open("gfw_res.txt", 'w') as fout:
        for state_id, flags in gfw_bypasses_ids_flags_dict.items():
            for f in flags:
                fout.write(','.join([state_id, f]) + '\n')

if args.dump_examples:
    with open("../data/concrete_examples_old") as fin:
        data = fin.readlines()
    with open("gfw_success_examples", 'w') as fout:
        for case in data:
            state_id = eval(case[:-1])['state_id']
            if str(state_id) in set(gfw_bypasses_ids):
                fout.write(case)

if args.dump_debug:
    with open("rst_gfw_not_rev_server.txt", 'w') as fout:
        for id in list(set(rst_id_ip_list) - set(server_recived_lst)):
            fout.write(id_to_filename[id])
    with open("rev_server_rst_gfw.txt", 'w') as fout:
        for id in list(set(rst_id_ip_list).intersection(set(server_recived_lst))):
            fout.write(id_to_filename[id])

if args.dump_empty_pcaps:
    with open("empty_pcap_lst.txt", 'w') as fout:
        for id in list(empty_pcap_set):
            fout.write(id + '\n')
