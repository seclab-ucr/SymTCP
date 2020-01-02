#!/bin/bash

if [ $EUID -ne 0 ]; then
    echo "This script should be run as root." > /dev/stderr
    exit 1
fi

current_time=$(date +"%Y%m%d%H%M%S")

snort_log_dir="/var/log/snort"
apache_log_dir="/var/log/apache2"
log_dir="../logs"
script_dir="../scripts"

function find_newest_filename() {
  local dir=$1
  local retval=$(ls $1 -t --ignore="alert" | head -n1)
  echo $retval
}

newest_snort=$(find_newest_filename $snort_log_dir)
echo "Newest Snort log filename: $newest_snort"
cp $snort_log_dir/$(find_newest_filename $snort_log_dir) $log_dir

newest_apache=$(find_newest_filename $apache_log_dir)
echo "Newest Apache log filename: $newest_apache"
apache_log_filename=apache.log.$current_time
echo "Apache log filename: $apache_log_filename"
cp $apache_log_dir/$(find_newest_filename $apache_log_dir) $log_dir/$apache_log_filename

bro_log_filename=bro.log.$current_time
echo "Bro log filename: $bro_log_filename"
cp notice.log $log_dir/$bro_log_filename
cp probe_dpi.log $log_dir/probe_dpi.log.$current_time
if [ "$2" ]; then
  rm *.log
fi

cp probe_dpi_result $log_dir/probe_dpi_result.$current_time

# change owner for copying log files
chown $USER: $log_dir/*
