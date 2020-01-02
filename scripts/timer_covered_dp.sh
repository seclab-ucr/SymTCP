#!/bin/bash

STARTED=0

while true; do
    scripts/get_covered_dp.py
    cat s2e-last/covered_dp
    wc -l s2e-last/covered_dp
    if [ $? == 0 ]; then
       if [ $STARTED == 0 ]; then
           echo "Started..."
           SECONDS=0
           STARTED=1
       fi
    fi
    date
    echo $SECONDS
    sleep `cat sleep_time`
done
