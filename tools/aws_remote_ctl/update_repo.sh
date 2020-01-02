#!/bin/bash

# update the repo
#python run_aws_experiment.py -U aws_url_list_20byte -R

# re-clone the repo
python2 run_aws_experiment.py -U aws_url_list_20byte -RC

# download test cases
#python2 run_aws_experiment.py -U aws_url_list_20byte --download-test-cases concrete_examples.20190611.sample.tar.gz


