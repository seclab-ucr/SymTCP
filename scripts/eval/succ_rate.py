#!/usr/bin/env python

import os
import sys

KIND_STR = {
    'ins': 'Insertion',
    'eva': 'Evasion'
}

early_succ_count = 0
unsolvable_count = 0
bug_count = 0
has_result_count = 0

gfw_succs = {}
bro_succs = {}
snort_succs = {}
nf_succs = {}

import argparse
parser = argparse.ArgumentParser(description='Get stats.')
parser.add_argument('result_file', type=argparse.FileType('r'), help='result file')
parser.add_argument('-G', '--gfw', default=False, action='store_true')
args = parser.parse_args()

for line in args.result_file:
    entry = eval(line)

    state_id = entry['state_id']

    r_max = max(entry['results'].keys())
    if r_max != entry['packet_num']:
        #print("%s succ early." % entry['state_id'])
        early_succ_count += 1

    has_result = False

    m = max(entry['results'].keys())
    for i in range(1, m + 1):
        if i == entry['packet_num'] and entry['drop_points']:
            kind = 'ins'
        else:
            kind = 'eva'

        result = entry['results'][i]
        for flags, result in result.iteritems():
            if isinstance(result, dict):
                has_result = True
                if args.gfw :
                    if result['server'] is True and result['gfw'] is False:
                        # gfw succ
                        if state_id not in gfw_succs:
                            gfw_succs[state_id] = { 'kind': kind, 'packet_num': i, 'dp': entry['drop_points'], 'ap': entry['accept_points'], 'flags': [] }
                        # sanity checks
                        # only one kind of succeeds is allowed for each state ID (either insertion of evasion)
                        assert gfw_succs[state_id]['kind'] == kind
                        # previous succeeded packet must have the same packet number (only flags can be different), becacuse we don't send later packets once succeed
                        assert gfw_succs[state_id]['packet_num'] == i
                        gfw_succs[state_id]['flags'].append(flags)
                else:
                    if result['apache'] is True:
                        if result['bro'] is False:
                            # bro succ
                            if state_id not in bro_succs:
                                bro_succs[state_id] = { 'kind': kind, 'packet_num': i, 'dp': entry['drop_points'], 'ap': entry['accept_points'], 'flags': [] }
                            # sanity checks
                            # only one kind of succeeds is allowed for each state ID (either insertion of evasion)
                            if bro_succs[state_id]['kind'] != kind:
                                assert bro_succs[state_id]['kind'] == 'eva' and kind == 'ins'
                                break
                            # previous succeeded packet must have the same packet number (only flags can be different), becacuse we don't send later packets once succeed
                            if bro_succs[state_id]['packet_num'] != i:
                                assert bro_succs[state_id]['packet_num'] < i
                                break
                            bro_succs[state_id]['flags'].append(flags)
                        if result['snort'] is False:
                            # snort succ
                            if state_id not in snort_succs:
                                snort_succs[state_id] = { 'kind': kind, 'packet_num': i, 'dp': entry['drop_points'], 'ap': entry['accept_points'], 'flags': [] }
                            # sanity checks
                            # only one kind of succeeds is allowed for each state ID (either insertion of evasion)
                            if snort_succs[state_id]['kind'] != kind:
                                assert snort_succs[state_id]['kind'] == 'eva' and kind == 'ins'
                                break
                            # previous succeeded packet must have the same packet number (only flags can be different), becacuse we don't send later packets once succeed
                            if snort_succs[state_id]['packet_num'] != i:
                                assert snort_succs[state_id]['packet_num'] < i
                                break
                            snort_succs[state_id]['flags'].append(flags)
                        if result['netfilter'] is False:
                            # netfilter succ
                            if state_id not in nf_succs:
                                nf_succs[state_id] = { 'kind': kind, 'packet_num': i, 'dp': entry['drop_points'], 'ap': entry['accept_points'], 'flags': [] }
                            # sanity checks
                            # only one kind of succeeds is allowed for each state ID (either insertion of evasion)
                            if nf_succs[state_id]['kind'] != kind:
                                assert nf_succs[state_id]['kind'] == 'eva' and kind == 'ins'
                                break
                            # previous succeeded packet must have the same packet number (only flags can be different), becacuse we don't send later packets once succeed
                            if nf_succs[state_id]['packet_num'] != i:
                                assert nf_succs[state_id]['packet_num'] < i
                                break
                            nf_succs[state_id]['flags'].append(flags)
            else:
                pass
    if has_result:
        has_result_count += 1
    else:
        if entry['packet_num'] == 1:
            print(line)
            bug_count += 1
        else:
            pass
            #print("Failed to send packets? %s" % entry) #entry['results'][r_max])

print("Early Succ: %d" % early_succ_count)
print("Early termination bug: %d" % bug_count)
print("Has result count: %d" % has_result_count)


# stats
if args.gfw:
    succ_num = 0
    ins_succ_num = 0
    eva_succ_num = 0
    for state_id in gfw_succs:
        succ_num += 1
        if gfw_succs[state_id]['kind'] == 'ins':
            ins_succ_num += 1
        elif gfw_succs[state_id]['kind'] == 'eva':
            eva_succ_num += 1
    print("GFW Succs: %d" % succ_num)
    print("GFW Insertion Succs: %d" % ins_succ_num)
    print("GFW Evasion Succs: %d" % eva_succ_num)

    fo = open('gfw_succ_list', 'w')
    for state_id in gfw_succs:
        for flags in gfw_succs[state_id]['flags']:
            fo.write("%s,%s,%s,%s\n" % (state_id, gfw_succs[state_id]['packet_num'], flags or 'UNCONSTRAINED', KIND_STR[gfw_succs[state_id]['kind']]))
    fo.close()
else:
    bro_succ_num = 0
    bro_ins_succ_num = 0
    bro_eva_succ_num = 0
    snort_succ_num = 0
    snort_ins_succ_num = 0
    snort_eva_succ_num = 0
    nf_succ_num = 0
    nf_ins_succ_num = 0
    nf_eva_succ_num = 0
    for state_id in bro_succs:
        bro_succ_num += 1
        if bro_succs[state_id]['kind'] == 'ins':
            bro_ins_succ_num += 1
        elif bro_succs[state_id]['kind'] == 'eva':
            bro_eva_succ_num += 1
    for state_id in snort_succs:
        snort_succ_num += 1
        if snort_succs[state_id]['kind'] == 'ins':
            snort_ins_succ_num += 1
        elif snort_succs[state_id]['kind'] == 'eva':
            snort_eva_succ_num += 1
    for state_id in nf_succs:
        nf_succ_num += 1
        if nf_succs[state_id]['kind'] == 'ins':
            nf_ins_succ_num += 1
        elif nf_succs[state_id]['kind'] == 'eva':
            nf_eva_succ_num += 1
    print("Bro Succs: %d" % bro_succ_num)
    print("Bro Insertion Succs: %d" % bro_ins_succ_num)
    print("Bro Evasion Succs: %d" % bro_eva_succ_num)
    print("Snort Succs: %d" % snort_succ_num)
    print("Snort Insertion Succs: %d" % snort_ins_succ_num)
    print("Snort Evasion Succs: %d" % snort_eva_succ_num)
    print("Netfilter Succs: %d" % nf_succ_num)
    print("Netfilter Insertion Succs: %d" % nf_ins_succ_num)
    print("Netfilter Evasion Succs: %d" % nf_eva_succ_num)

    fo = open('bro_succ_list', 'w')
    for state_id in bro_succs:
        for flags in bro_succs[state_id]['flags']:
            fo.write("%s,%s,%s,%s\n" % (state_id, bro_succs[state_id]['packet_num'], flags or 'UNCONSTRAINED', KIND_STR[bro_succs[state_id]['kind']]))
    fo.close()

    fo = open('snort_succ_list', 'w')
    for state_id in snort_succs:
        for flags in snort_succs[state_id]['flags']:
            fo.write("%s,%s,%s,%s\n" % (state_id, snort_succs[state_id]['packet_num'], flags or 'UNCONSTRAINED', KIND_STR[snort_succs[state_id]['kind']]))
    fo.close()

    fo = open('nf_succ_list', 'w')
    for state_id in nf_succs:
        for flags in nf_succs[state_id]['flags']:
            fo.write("%s,%s,%s,%s\n" % (state_id, nf_succs[state_id]['packet_num'], flags or 'UNCONSTRAINED', KIND_STR[nf_succs[state_id]['kind']]))
    fo.close()





