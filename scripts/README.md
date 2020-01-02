## Instructions

**probe_dpi.py**: script to probe DPI (Bro, GFW, etc.)

If probing the GFW, make a _server_list_ file in the working directory. Each line is a different IP address of a server. 
Make sure to have more than 30 servers in order to rotate, because the GFW will block a server for 90 seconds if we trigger RST. 
And probing each server takes at least 3 seconds.
For probing other DPIs, it will use the server IP in the script.

Probing with a concrete example file

```./probe_dpi.py <concrete example file>```

Probing with a concrete example file and dump packet trace for each test case. 
(Packet traces will be stored at ./pcap)

```./probe_dpi.py -D <concrete example file>```

Probing the GFW with a concrete example file and dump packet trace for each test case. 
(Packet traces will be stored at ./pcap)

```./probe_dpi.py --gfw -D <concrete example file>```

