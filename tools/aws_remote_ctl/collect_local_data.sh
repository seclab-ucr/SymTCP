#!/bin/bash

# move logs to the logs folder
python2 run_aws_experiment.py -U aws_url_list_20byte -C

# download result for local experiment
python2 run_aws_experiment.py -U aws_url_list_20byte -DL -LDD local_data

# process downloaded result
python2 run_aws_experiment.py -U aws_url_list_20byte -PDL -LDD local_data

