#!/bin/bash

# download result for local experiment
python2 run_aws_experiment.py -U aws_url_list_20byte -DG -LDD gfw_data

# process downloaded result
python2 run_aws_experiment.py -U aws_url_list_20byte -PDG -LDD gfw_data

