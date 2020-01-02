#!/usr/bin/env python

import os
import sys

from parse_s2e_result import parse_s2e_result
from triage import triage

#PROJECT_DIR = '/home/alan/Work/extraspace/s2e/projects/tcp'


def process_result(result_dir):
	print("Processing s2e result '%s'" % result_dir)
	#idx = int(result_dir[len('s2e-out-')])

	try:
	    f = open(result_dir + '/parent_idx', 'r')
	    parent_idx = int(f.read())
	    f.close()
	except IOError:
	    pass

	log_file = result_dir + '/debug.txt'

	# extract concrete packets
	concrete_packets = parse_s2e_result(log_file)
	f = open(result_dir + '/packets', 'w')
	f.write("%s" % concrete_packets)
	f.close()

	# find unsatisfied branches
	yes_branches, no_branches, never_branches = triage(log_file)
	f = open(result_dir + '/branches', 'w')
	branches = { 'yes': yes_branches, 'no': no_branches, 'never': never_branches }
	f.write("%s" % branches)
	f.close()

	print("%d concrete packets, %d yes, %d no, %d never" % 
	        (len(concrete_packets), len(yes_branches), len(no_branches), len(never_branches)))

	print("Done.")

if __name__ == "__main__":
    result_dir = sys.argv[1]
    process_result(result_dir)

