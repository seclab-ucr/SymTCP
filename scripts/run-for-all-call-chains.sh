#!/bin/bash

S2E_DIR=$HOME/Work/extraspace/s2e
DROPBOX_DIR=$HOME/Dropbox/s2e/res


CALLCHAIN_FILE=$1
BLACKLIST_FILE=$2

NUM_CALL_CHAINS=`wc -l $1 | cut -d\  -f1`

TIMEOUT=3600


rm $DROPBOX_DIR/*

for i in `seq 1 $NUM_CALL_CHAINS`;
do
    echo $i
    cd $S2E_DIR
    ./gen_director.py $CALLCHAIN_FILE $BLACKLIST_FILE $i > director_$i.txt
    mv director_$i.txt director.txt

    cd projects/tcp
    ./launch-s2e.sh &

    S2E_PID=$!

    # wait for s2e to start up
    sleep 15
    QEMU_PID=`cat qemu.pid`

    nc localhost 5555 &

    NC_PID=$!

    (sleep $TIMEOUT && kill $QEMU_PID) &

    wait $S2E_PID

    if [ $? -eq 0 ];
    then 
        touch ${DROPBOX_DIR}/${i}_ok
    else
        touch ${DROPBOX_DIR}/${i}_err
    fi

    kill -9 $NC_PID

    rm qemu.pid

    # process results
    # generate concrete packets
    ./parse-s2e-results.py > s2e-last/packets
    # find unsatisfied branches
    ./triage.py > s2e-last/unsat_branches

done




