import re
from collections import Counter
import argparse

TCP_FLAGS = {'SYN', 'RST', 'ACK', 'FIN', 'RSTACK', 'FINACK'}

parser = argparse.ArgumentParser()
parser.add_argument('-LD', '--logs-dir', default='.', type=str, help='dir that contains log files')
parser.add_argument('-S', "--bypass-stats", action="store_true", default=False)
parser.add_argument('-I', "--bypass-ids", action="store_true", default=False)
parser.add_argument('-IF', "--bypass-ids-flags", action="store_true", default=False)
parser.add_argument('-C', "--bypass-cases", action="store_true", default=False)
parser.add_argument('-DSD', "--dump-success-dp-stats", action="store_true", default=False)
parser.add_argument('-D', "--dump-examples", action="store_true", default=False)
parser.add_argument('-DPDS', "--dump-per-dp-stats", action="store_true", default=False)
parser.add_argument('-A', "--dump-apache-misses", action="store_true", default=False)
parser.add_argument('-DAPDS', "--dump-apache-per-dp-stats", action="store_true", default=False)
parser.add_argument('-T', "--test-cases")
args = parser.parse_args()

log_dir = args.logs_dir + '/'

ID_PATTERN = r'ultrasurf#\w+#'

def find_bad_keyword_id_one_line(text):
    m = re.search(ID_PATTERN, text)
    if m:
        return m.group(0)
    else:
        #print("[PARSER][error] No Id found in line: ", text)
        return None

def find_all_bad_keyword_ids_one_file(file_dir):
    with open(file_dir, 'r', errors='ignore') as fin:
        data = fin.readlines()
    state_ids = []
    for d in data:
        state_id_str = find_bad_keyword_id_one_line(d)
        if state_id_str:
            state_id_flag = state_id_str.split('#')[1]
            if state_id_flag.split('_')[-1] in TCP_FLAGS:
                state_id, flag = '_'.join(state_id_flag.split('_')[:-1]), state_id_flag.split('_')[-1]
            else:
                state_id = state_id_str.split('#')[1]
            state_ids.append(state_id)
    # should not be any duplicate, but nice to double-check
    state_ids = list(set(state_ids))
    return state_ids

def find_all_bad_keyword_ids_with_flags_one_file(file_dir):
    with open(file_dir, 'r', errors='ignore') as fin:
        data = fin.readlines()
    state_ids = []
    for d in data:
        state_id_str = find_bad_keyword_id_one_line(d)
        if state_id_str:
            state_id = state_id_str.split('#')[1]
            state_ids.append(state_id)
    # should not be any duplicate, but nice to double-check
    state_ids = list(set(state_ids))
    return state_ids

def map_to_state_id(state_id_flags):
    if state_id_flags.split('_')[-1] in TCP_FLAGS:
        state_id = '_'.join(state_id_flags.split('_')[:-1])
    else:
        state_id = state_id_flags
    return state_id

def map_to_flags(state_id_flags):
    if state_id_flags.split('_')[-1] in TCP_FLAGS:
        flags = state_id_flags.split('_')[-1]
    else:
        flags = 'Unconstrained'
    return flags

def extract_ids(fname):
    return find_all_bad_keyword_ids_one_file(fname)

def extract_ids_flags(fname):
    return find_all_bad_keyword_ids_with_flags_one_file(fname)

apache_ids = extract_ids(log_dir + 'apache.log')
apache_ids_set = set(apache_ids)
apache_ids_flags = extract_ids_flags(log_dir + 'apache.log')
apache_ids_flags_set = set(apache_ids_flags)

snort_ids = extract_ids(log_dir + 'processed_snort.log')
snort_ids_set = set(snort_ids)
snort_ids_flags = extract_ids_flags(log_dir + 'processed_snort.log')
snort_ids_flags_set = set(snort_ids_flags)

bro_ids = extract_ids(log_dir + 'bro.log')
bro_ids_set = set(bro_ids)
bro_ids_flags = extract_ids_flags(log_dir + 'bro.log')
bro_ids_flags_set = set(bro_ids_flags)

netfilter_ids = extract_ids(log_dir + 'processed_netfilter.log')
netfilter_ids_set = set(netfilter_ids)
netfilter_ids_flags = extract_ids_flags(log_dir + 'processed_netfilter.log')
netfilter_ids_flags_set = set(netfilter_ids_flags)

print('Num of Apache log:', len(apache_ids))
print('Num of Snort log:', len(snort_ids))
print('Num of Bro log:', len(bro_ids))
print('Num of Netfilter log:', len(netfilter_ids))

def get_bypass_state_id(apache_ids, ids_ids):
    bypasses = []
    for state_id in apache_ids:
        if state_id not in ids_ids:
            bypasses.append(state_id)
    return bypasses

def get_bypass_state_id_flags(apache_ids_flags, ids_ids_flags_set):
    bypasses_dict = {}
    bypasses = []
    for state_id_flags in apache_ids_flags:
        if state_id_flags not in ids_ids_flags_set:
            state_id = map_to_state_id(state_id_flags)
            flags = map_to_flags(state_id_flags)
            if state_id not in bypasses_dict:
                bypasses_dict[state_id] = [flags]
            else:
                bypasses_dict[state_id].append(flags)
            bypasses.append(state_id)
    return list(set(bypasses)), bypasses_dict

def get_apache_dict(apache_ids_flags):
    apache_dict = {}
    apache_state_ids = []
    for state_id_flags in apache_ids_flags:
        state_id = map_to_state_id(state_id_flags)
        flags = map_to_flags(state_id_flags)
        if state_id not in apache_dict:
            apache_dict[state_id] = [flags]
        else:
            apache_dict[state_id].append(flags)
        apache_state_ids.append(state_id)
    return list(set(apache_state_ids)), apache_dict

def dump_bypass_ids(fname, bypasses):
    with open(fname, 'w') as fout:
        for state_id in sorted(bypasses):
            fout.write(str(state_id) + '\n')

def dump_bypass_ids_flags(fname, bypasses_dict):
    with open(fname, 'w') as fout:
        for state_id, flags in bypasses_dict.items():
            for f in flags:
                fout.write(','.join([state_id, f]) + '\n')

def dump_bypass_examples(fname, example_set, bypasses):
    with open(fname, 'w') as fout:
        for state_id in bypasses:
            try:
                fout.write(example_set[state_id])
            except KeyError:
                print(('%s does not exist!') % state_id)
                continue

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


snort_bypasses, snort_bypasses_dict = get_bypass_state_id_flags(apache_ids_flags, snort_ids_flags_set)
bro_bypasses, bro_bypasses_dict = get_bypass_state_id_flags(apache_ids_flags, bro_ids_flags_set)
netfilter_bypasses, netfilter_bypasses_dict = get_bypass_state_id_flags(apache_ids_flags, netfilter_ids_flags_set)

if args.bypass_stats:
    print('Num of Snort bypasses:', len(snort_bypasses))
    print('Num of Bro bypasses:', len(bro_bypasses))
    print('Num of Netfilter bypasses:', len(netfilter_bypasses))

if args.test_cases:
    example_set = {}
    with open(args.test_cases, 'r') as fin:
        data = fin.readlines()
    for d in data:
        state_id = eval(d[:-1])['state_id']
        example_set[state_id] = d

if args.test_cases and args.dump_apache_misses:
    with open('apache_misses.txt', 'w') as fout:
        for d in data:
            state_id = eval(d[:-1])['state_id']
            if state_id not in set(apache_ids):
                fout.write(d)

if args.bypass_ids:
    dump_bypass_ids('bro_success_ids.txt', bro_bypasses)
    dump_bypass_ids('snort_success_ids.txt', snort_bypasses)
    dump_bypass_ids('netfilter_success_ids.txt', netfilter_bypasses)

if args.bypass_ids_flags:
    dump_bypass_ids_flags('bro_success_ids_flags.txt', bro_bypasses_dict)
    dump_bypass_ids_flags('snort_success_ids_flags.txt', snort_bypasses_dict)
    dump_bypass_ids_flags('netfilter_success_ids_flags.txt', netfilter_bypasses_dict)

if args.bypass_cases:
    dump_bypass_examples("bro_success_examples.txt", example_set, bro_bypasses)
    dump_bypass_examples("snort_success_examples.txt", example_set, snort_bypasses)
    dump_bypass_examples("netfilter_success_examples.txt", example_set, netfilter_bypasses)

if args.dump_per_dp_stats and args.test_cases:
    dump_per_dp_bypass_stats('bro_per_dp_stats.txt', bro_bypasses_dict, example_set)
    dump_per_dp_bypass_stats('snort_per_dp_stats.txt', snort_bypasses_dict, example_set)
    dump_per_dp_bypass_stats('netfilter_per_dp_stats.txt', netfilter_bypasses_dict, example_set)

if args.test_cases and args.dump_success_dp_stats:
    dump_success_dp_stats("bro_success_paths.csv", bro_bypasses, example_set)
    dump_success_dp_stats("snort_success_paths.csv", snort_bypasses, example_set)
    dump_success_dp_stats("netfilter_success_paths.csv", netfilter_bypasses, example_set)

if args.test_cases and args.dump_apache_per_dp_stats:
    apache_state_ids, apache_dict = get_apache_dict(apache_ids_flags)
    dump_per_dp_bypass_stats('apache_per_dp_stats.txt', apache_dict, example_set)
    dump_success_dp_stats('apache_per_dp_overall_stats.txt', apache_state_ids, example_set)
