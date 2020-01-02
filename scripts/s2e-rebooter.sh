#!/bin/bash


QEMU_PID_FILE="qemu.pid"

TIMEOUT=3600

# wait until current s2e instance finishes

if [ -f "$QEMU_PID_FILE" ] && [ -s "$QEMU_PID_FILE" ]
then 
    QEMU_PID=`cat $QEMU_PID_FILE`
    echo "Qemu pid is $QEMU_PID. waiting for pid $QEMU_PID."
    wait $QEMU_PID
fi

PROC_NUM=`ps -ef | grep launch-s2e.sh | wc -l`
if [ $PROC_NUM -gt 1 ] 
then
    echo "There's already a launch-s2e.sh running. waiting for it."
    sleep 1
    while [ $PROC_NUM -ne 1 ]
    do
        PROC_NUM=`ps -ef | grep launch-s2e.sh | wc -l`
        sleep 1
    done
fi

while true
do
    ./launch-s2e.sh &
    S2E_PID=$!

    # wait for guest OS to boot up
    sleep 15
    QEMU_PID=`cat $QEMU_PID_FILE`

    (sleep $TIMEOUT && kill $QEMU_PID) &

    wait $S2E_PID

    rm $QEMU_PID_FILE

    sleep 2
done




