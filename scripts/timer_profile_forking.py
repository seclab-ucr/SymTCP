#!/usr/bin/env python

import glob
import os
import sys
import datetime
import time


while True:
    print("Profiling forking...")
    os.system("./profile_forking.sh")
    res = glob.glob("forking_2019*.raw")
    #print(res)
    assert len(res) == 1
    dt = res[0].split('.')[0].split('_', 1)[1]
    dt_cur = datetime.datetime.strptime(dt, '%Y%m%d_%H%M%S')
    #print(dt_cur)

    res = glob.glob("forking_profile/forking_2019*.raw")
    last_dt = None
    #print(res)
    for r in res:
        dt2 = r.split('/')[1].split('.')[0].split('_', 1)[1]
        dt2 = datetime.datetime.strptime(dt2, '%Y%m%d_%H%M%S')
        if last_dt is None:
            last_dt = dt2
        elif dt2 > last_dt:
            last_dt = dt2
    print("Last time: %s" % last_dt)

    if last_dt:
        print("Generating diff...")
        os.system("./diff_forking.py forking_profile/forking_%s forking_%s > forking_%s.diff" % (last_dt.strftime("%Y%m%d_%H%M%S"), dt_cur.strftime("%Y%m%d_%H%M%S"), dt_cur.strftime("%Y%m%d_%H%M%S")))
        os.system("scripts/file_addr2line.py forking_%s.diff" % dt_cur.strftime("%Y%m%d_%H%M%S"))

    os.system("mv forking_2019* forking_profile/")

    print("Sleeping for 5 minutes...")
    time.sleep(60 * 5)
    



