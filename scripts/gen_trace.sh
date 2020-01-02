#!/bin/bash

S2EDIR=/home/alan/Work/extraspace/s2e
S2EINSTALL=$S2EDIR/install
S2EBUILD=$S2EDIR/build/s2e
MODDIR=.

mkdir s2e-last/traces

$S2EINSTALL/bin/tbtrace -trace=s2e-last/ExecutionTracer.dat -outputdir=s2e-last/traces -moddir=$MODDIR -printMemory
#gdb --args $S2EBUILD/tools-debug/tools/tbtrace/tbtrace -trace=s2e-last/ExecutionTracer.dat -outputdir=s2e-last/traces -moddir=$MODDIR -printMemory
#lldb -- $S2EBUILD/tools-debug/tools/tbtrace/tbtrace -trace=s2e-last/ExecutionTracer.dat -outputdir=s2e-last/traces -moddir=$MODDIR -printMemory

