#!/usr/bin/env python

import os
import re
import sys

from multiprocessing import Pool, Process

from s2e_utils import *

# Be careful of '.'! We are in re.DOTALL mode. Replace all '.' with '[^\n]' if we only want to match in a single line.

# test case generated when it exits tcp_v4_rcv
#mid_test_case_pattern_str = "State (\d+?)\] TCPSymbolizer: Leaving tcp_v4_rcv\. (\d+?)\n[^\n]+\n[^\n]+?TCPSymbolizer: (\(.*?)\d+ \[[^\n]+?\] TestCaseGenerator: [^\n]+?\n[^\n]+?TestCaseGenerator:(.*?)\n[^\sv]"
#mid_test_case_pattern = re.compile(mid_test_case_pattern_str, re.MULTILINE | re.DOTALL)

test_case_pattern_str = "Socket state: (\d+?)\n[^\n]+? Accept points reached: ([^\n]*?)\n[^\n]+? Drop points reached: ([^\n]*?)\n[^\n]+?: (\(.*?)\d+ [^\n]+? Terminating state early: ([^\n]+?)\n[^\n]+? generating test case at address (0x[0-9a-fA-F]{16})\n\d+ \[[^\n]*?State (\d+)\] TestCaseGenerator:(.*?)\n[^\sv]"
test_case_pattern = re.compile(test_case_pattern_str, re.MULTILINE | re.DOTALL)
var_pattern = "\s*(.*?) = \{(.*?)\};.*"
var_pattern = re.compile(var_pattern)

func_ret_pattern_str = "TCPSymbolizer: Leaving tcp_v4_rcv\. (\d)\n\d+ \[[^\n]*?State (\d+)\] TCPSymbolizer: Socket state: (\d+)\n"
func_ret_pattern = re.compile(func_ret_pattern_str, re.MULTILINE)


def collect_packet_examples(fname):
    f = open(fname, 'r')
    content = f.read()
    f.close()

    # the socket state after processing a packet
    # ideally it should be the socket state when leaving tcp_v4_rcv
    # but now for the last packet, we terminate execution when it reaches a drop point, 
    # so in this way we don't know the state when it leaves tcp_v4_rcv, maybe change it later
    sk_state_map = {}
    skstate_fname = os.path.join(os.path.dirname(fname), 'sk_states')
    fo = open(skstate_fname, 'w')

    for m in func_ret_pattern.finditer(content):
        #print("------------------Socket state------------------")
        #print(m.group(0))
        #print("------------------------------------------------")
        packet_idx = int(m.group(1))
        state_id = int(m.group(2))
        sk_state = int(m.group(3))

        if state_id not in sk_state_map:
            sk_state_map[state_id] = {}
        sk_state_map[state_id][packet_idx] = int(sk_state)

    fo.write("%s" % sk_state_map)
    fo.close()

    all_test_cases = {}
    ce_fname = os.path.join(os.path.dirname(fname), 'concrete_examples')
    fo = open(ce_fname, 'w')

    for m in test_case_pattern.finditer(content):
        #print("------------------Final Test Case------------------")
        #print(m.group(0))
        #print("---------------------------------------------------")
        sk_state = int(m.group(1))
        accept_points = m.group(2).split()
        drop_points = m.group(3).split()
        constraints = m.group(4)
        reason = m.group(5)
        pc = m.group(6)
        state_id = m.group(7)
        vars_ = m.group(8)
        vars_ = vars_.split('\n')
        pkt_num = 0
        example = {}
        for var in vars_:
            if var == '': continue
            var = var.strip()
            #print(var)
            m2 = var_pattern.match(var)
            assert m2
            k = m2.group(1)
            pkt_idx, _ = get_packet_idx(k)
            if pkt_idx > pkt_num:
                pkt_num = pkt_idx
            v = eval('[' + m2.group(2) + ']')
            example[k] = v
        assert pkt_num > 0

        if reason == "bad checksum case.":
            state_id = state_id + '_c_' + pc + '_' + str(pkt_num)
        else:
            assert state_id not in all_test_cases

        all_test_cases[state_id] = {}
        all_test_cases[state_id]['state_id'] = state_id
        all_test_cases[state_id]['packet_num'] = pkt_num
        all_test_cases[state_id]['sk_state'] = { pkt_num: sk_state }
        all_test_cases[state_id]['accept_points'] = accept_points
        all_test_cases[state_id]['drop_points'] = drop_points
        all_test_cases[state_id]['constraints'] = constraints
        all_test_cases[state_id]['example'] = example
        fo.write("%s\n" % all_test_cases[state_id])

    fo.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Get concrete examples from debug.txt log.')
    #parser.add_argument('--sid', type=str, help='Get concrete example of specific state.')
    parser.add_argument('-d', '--dir', type=str, default='s2e-last', help='S2E result directory. If not specified, s2e-last is used.')
    args = parser.parse_args()

    s2e_output_files = get_s2e_output_files(args.dir)
    p = Pool(len(s2e_output_files))
    p.map(collect_packet_examples, s2e_output_files)

    # merge all concrete examples
    all_test_cases = {}
    sk_state_map = {}

    for fname in s2e_output_files:
        skstate_fname = os.path.join(os.path.dirname(fname), 'sk_states')
        f = open(skstate_fname, 'r')
        content = f.read()
        f.close()
        mp = eval(content)
        for state_id in mp:
            if state_id not in sk_state_map:
                sk_state_map[state_id] = {}
            sk_state_map[state_id].update(mp[state_id])

    reversed_fork_rel = get_reversed_fork_relations(s2e_output_files)

    for fname in s2e_output_files:
        ce_fname = os.path.join(os.path.dirname(fname), 'concrete_examples')
        f = open(ce_fname, 'r')
        for line in f:
            entry = eval(line)
            if entry['state_id'] in all_test_cases:
                print("ERROR! state_id %s occurs multiple times!" % entry['state_id'])
            else:
                all_test_cases[entry['state_id']] = entry

            sid = int(entry['state_id'].split('_')[0])
            for i in range(entry['packet_num']-1, 0, -1):
                while i not in sk_state_map.get(sid, {}) and sid in reversed_fork_rel:
                    sid = reversed_fork_rel[sid]
                if i in sk_state_map[sid]:
                    entry['sk_state'][i] = sk_state_map[sid][i]
        
            print(entry)
        f.close()

    #if args.sid:
    #    if args.sid in all_test_cases:
    #        print(all_test_cases[args.sid])
    #    else:
    #        print("SID %d cannot be found." % args.sid)


