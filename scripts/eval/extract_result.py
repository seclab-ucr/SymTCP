#!/usr/bin/env python

import sys

f = open(sys.argv[1], 'r')

for line in f:
    entry = eval(line)
    entry2 = {'state_id': entry['state_id'], 'packet_num': entry['packet_num'], 'accept_points': entry['accept_points'], 'drop_points': entry['drop_points'], 'sk_state': entry['sk_state'], 'results': entry['results']}
    print("%s" % entry2)

f.close()

