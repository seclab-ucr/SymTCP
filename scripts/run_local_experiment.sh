#!/bin/bash

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root"
   exit
fi

current_time=$(date +"%Y%m%d%H%M%S")
dpi_dir="../tools/dpi_sys_confs"
log_dir="../logs"
script_dir="../scripts"

clean_up() {
  echo "INT/TERM signal received!"
  pkill python
  pkill bro
  pkill bro
  pkill snort
  pkill tcpdump
  pkill dumpcap
  # rm 0
  # Clean up iptales rule
  iptables -D OUTPUT -p tcp --dport 80 -m conntrack --ctstate ESTABLISHED -m string --algo bm --string "ultrasurf" -j NFLOG --nflog-group 66 --nflog-prefix netfilter
  #sudo iptables -D INPUT -m string --algo bm --string "THIS_IS_A_BAD_KEYWORD" -j NFLOG --nflog-group 88 --nflog-prefix netfilter
  exit
}

# Trap Ctrl+C
trap clean_up INT TERM

echo "0: Cleaning up log dir..."
rm -rf $log_dir
mkdir $log_dir
rm nohup.out
# still unsure why dumpcap does not work in some cases
#chown ubuntu: $log_dir
service apache2 restart

echo "1: Setting up iptables rules for Netfilter..."
iptables -D OUTPUT -p tcp --dport 80 -m conntrack --ctstate ESTABLISHED -m string --algo bm --string "ultrasurf" -j NFLOG --nflog-group 66 --nflog-prefix netfilter
iptables -D OUTPUT -p tcp --dport 80 -m conntrack --ctstate ESTABLISHED -m string --algo bm --string "ultrasurf" -j NFLOG --nflog-group 66 --nflog-prefix netfilter
iptables -D OUTPUT -p tcp --dport 80 -m conntrack --ctstate ESTABLISHED -m string --algo bm --string "ultrasurf" -j NFLOG --nflog-group 66 --nflog-prefix netfilter
iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate ESTABLISHED -m string --algo bm --string "ultrasurf" -j NFLOG --nflog-group 66 --nflog-prefix netfilter
#iptables -A INPUT -m string --algo bm --string "THIS_IS_A_BAD_KEYWORD" -j NFLOG --nflog-group 88 --nflog-prefix netfilter

echo "2: Running dumpcap..."
nohup dumpcap -i nflog:66 -w $log_dir/netfilter.pcap.$current_time &
#> $log_dir/netfilter.log.$current_time

echo "3: Running Snort..."
nohup snort -c /etc/snort/snort.conf -i eth0 &
#> $log_dir/snort.log.$current_time

echo "4: Running Bro..."
nohup /usr/local/bro/bin/bro -i eth0 $dpi_dir/bro/detect-bad-keywords.bro &
#> $log_dir/bro.log.$current_time

# sleep 180s or Snort will pick up mid-stream packets without requirement of 3WHS
sleep 180

echo "5: Running probe_dpi.py..."
nohup python $script_dir/probe_dpi.py -P -I eth0 -F -N $2 -S $3 -p $4 ~/$1 &

while true
do continue
  # infinite loop
done
