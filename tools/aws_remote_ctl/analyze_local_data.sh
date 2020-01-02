#!/bin/bash

# analyzse gfw pcaps
python ../data_processing/log_analyzer.py -LD local_data/sym-tcp/logs/ -T ../../data/concrete_examples.final.new.sample -S -I -IF -C -DSD -DPDS -A -DAPDS

