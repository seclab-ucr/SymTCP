#!/bin/bash

sudo iptables -t raw -A OUTPUT -p tcp --dport 80 --tcp-flags RST,ACK RST -m ttl ! --ttl-eq 163 -j DROP

