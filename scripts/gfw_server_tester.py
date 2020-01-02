#!/usr/bin/env python

import os


f = open('server_list', 'r')

for line in f:
    ip = line.strip()
    os.system('curl http://%s/ultrasurf' % ip)
    raw_input('Press ENTER to continue...')

f.close()

