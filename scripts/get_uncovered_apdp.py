#!/usr/bin/env python

import os
import sys

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))

all_dp = {}
all_ap = {}

def load_all_dp():
    f = open(SCRIPT_PATH + '/all_dp', 'r')
    for line in f:
        dp = line.split(' ', 1)[0]
        assert dp not in all_dp
        all_dp[dp] = True
    f.close()

def load_all_ap():
    f = open(SCRIPT_PATH + '/all_ap', 'r')
    for line in f:
        ap = line.split(' ', 1)[0]
        assert ap not in all_ap
        all_ap[ap] = True
    f.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Get uncovered accept/drop points.')
    parser.add_argument('output_dirs', nargs='*', default=['s2e-last'], help='S2E output dirs.')
    parser.add_argument('-s', dest='skip_processing', default=False, action='store_true', help='Skip log processing.')
    args = parser.parse_args()

    if not args.skip_processing:
        for result_dir in args.output_dirs:
            os.system(SCRIPT_PATH + "/get_covered_apdp.py " + result_dir)

    load_all_dp()
    load_all_ap()

    total_dp_num = len(all_dp)
    total_ap_num = len(all_ap)

    for result_dir in args.output_dirs:
        f = open(result_dir + "/covered_dp")
        for line in f:
            parts = line.split()
            dp = parts[0]
            if dp in all_dp:
                del all_dp[dp]
        f.close()

        f = open(result_dir + "/covered_ap")
        for line in f:
            parts = line.split()
            ap = parts[0]
            if ap in all_ap:
                del all_ap[ap]
        f.close()

    print("Uncovered DP:")
    for dp in all_dp:
        print(dp)
    print("Covered DP: %d" % (total_dp_num - len(all_dp)))

    print("Uncovered AP:")
    for ap in all_ap:
        print(ap)
    print("Covered AP: %d" % (total_ap_num - len(all_ap)))


