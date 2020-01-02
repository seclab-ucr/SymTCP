#!/bin/bash

# clean apache log
python2 run_aws_experiment.py -U aws_url_list_20byte -DA

# run local experiment
python2 run_aws_experiment.py -U aws_url_list_20byte -DF concrete_examples.20190611.sample -PL 20 -L
