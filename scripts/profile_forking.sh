#!/bin/bash

TS=`date +%Y%m%d_%H%M%S`

grep Forking s2e-last/*/info.txt > forking_$TS.raw

cut -d\  -f13 forking_$TS.raw | sort | uniq -c | sort -nr > forking_$TS

/home/alan/Work/s2e/s2e/projects/tcp/scripts/file_addr2line.py forking_$TS


