#!/home/alan/Work/s2e/s2e-env/venv/bin/python

import errno
import os
import random
import signal
import sys
import time

from time import sleep

from scapy.all import sr1, TCP, IP, Raw, hexdump, sr, send, conf, L3RawSocket

from z3 import *

set_param('model_compress', False)


START_FROM = 1

SYN = 0x02
RST = 0x04
ACK = 0x10

SERVER_IP = "172.20.0.2"
#SERVER_IP = "127.0.0.1"
SERVER_PORT = 5555

conf.L3socket=L3RawSocket

# bad keyword
HTTP_REQ = "A"


def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    enable_other_packets()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


def disable_other_packets():
    os.system("iptables -t raw -A OUTPUT -p tcp --dport 5555 -m ttl ! --ttl-eq 163 -j DROP")

def enable_other_packets():
    os.system("iptables -t raw -D OUTPUT -p tcp --dport 5555 -m ttl ! --ttl-eq 163 -j DROP")


def get_value_from_model(m, d, size):
    val = [0] * size
    if is_K(m[d]):
        for i in range(size):
            val[i] = m[d].arg(i).as_long()
    elif isinstance(m[d], FuncInterp):
        for i in range(size):
            if i >= m[d].num_entries():
                break
            e = m[d].entry(i)
            assert e.num_args() == 1
            val[e.arg_value(0).as_long()] = e.value().as_long()
    return val

def solve_constraints(constraints, args={}):
    s = Solver()
    constraints = constraints.split('\n')
    constraints_new = []
    client_isn_var = None
    server_isn_var = None
    for line in constraints:
        if line and line != '(check-sat)' and line != '(exit)':
            constraints_new.append(line)
        if line.startswith("(declare-") and "tcp_seq_num1_" in line:
            client_isn_var = line.split()[1]
        if line.startswith("(declare-") and "tcp_svr_isn" in line:
            server_isn_var = line.split()[1]
    if 'client_isn' in args and client_isn_var:
        client_isn = args['client_isn']
        v = []
        for i in range(4):
            v.append(client_isn % 256)
            client_isn /= 256
        v.reverse()
        # client ISN is network-order because we symbolized a packet field
        constraints_new.append("(assert (and (= (select %s (_ bv0 32) ) #x%02x) (= (select %s (_ bv1 32) ) #x%02x) (= (select %s (_ bv2 32) ) #x%02x) (= (select %s (_ bv3 32) ) #x%02x) ) )" % (client_isn_var, v[0], client_isn_var, v[1], client_isn_var, v[2], client_isn_var, v[3]))
    if 'server_isn' in args and server_isn_var:
        server_isn = args['server_isn']
        v = []
        for i in range(4):
            v.append(server_isn % 256)
            server_isn /= 256
        # server ISN is host order because we symbolized a local variable
        constraints_new.append("(assert (and (= (select %s (_ bv0 32) ) #x%02x) (= (select %s (_ bv1 32) ) #x%02x) (= (select %s (_ bv2 32) ) #x%02x) (= (select %s (_ bv3 32) ) #x%02x) ) )" % (server_isn_var, v[0], server_isn_var, v[1], server_isn_var, v[2], server_isn_var, v[3]))
    constraints = '\n'.join(constraints_new)

    print(constraints)

    F = parse_smt2_string(constraints)
    #print(F.sexpr())
    s.add(F)
    res = s.check()
    print(res)
    if res == sat:
        example = {}
        m = s.model()
        print(m)
        for d in m:
            k = str(d)
            if 'tcp_seq_num' in k:
                example[k] = get_value_from_model(m, d, 4)
            elif 'tcp_ack_num' in k:
                example[k] = get_value_from_model(m, d, 4)
            elif 'tcp_doff_reserved_flags' in k:
                example[k] = get_value_from_model(m, d, 1)
            elif 'tcp_flags' in k:
                example[k] = get_value_from_model(m, d, 1)
            elif 'tcp_win' in k:
                example[k] = get_value_from_model(m, d, 2)
            elif 'tcp_urg_ptr' in k:
                example[k] = get_value_from_model(m, d, 2)

        return example

    return None

# update the packet with concrete example of packet with index `idx`
def update_pkt_with_example(pkt, example, idx):
    print "=========="
    for k, v in example.iteritems():
        if 'tcp_header' + str(idx) in k:
            octets = example[k]
            print('tcp_header: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].seq = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
            pkt[TCP].ack = (octets[4] << 24) + (octets[5] << 16) + (octets[6] << 8) + octets[7]
            pkt[TCP].dataofs = ((octets[8] & 0xF0) >> 4)
            pkt[TCP].reserved = ((octets[8] & 0x0E) >> 1)
            pkt[TCP].flags = ((octets[8] & 0x01) << 8) + octets[9]
            #pkt[TCP].flags = octets[9]
            #pkt[TCP].flags = 'A'
            pkt[TCP].window = (octets[10] << 8) + octets[11]
            #pkt[TCP].chksum = (octets[12] << 8) + octets[13]
            pkt[TCP].urgptr = (octets[14] << 8) + octets[15]
            #pkt[TCP].payload = [ chr(o) for o in octets[16:] ]
        elif 'tcp_seq_num' + str(idx) in k:
            octets = example[k]
            print('tcp_seq_num: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].seq = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
        elif 'tcp_ack_num' + str(idx) in k:
            octets = example[k]
            print('tcp_ack_num: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].ack = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
        elif 'tcp_doff_reserved_flags' + str(idx) in k:
            octets = example[k]
            print('tcp_doff_reserved_flags: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].dataofs = octets[0] >> 4
            pkt[TCP].reserved = octets[0] & 0xf
        elif 'tcp_flags' + str(idx) in k:
            octets = example[k]
            print('tcp_flags: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].flags = octets[0]
        elif 'tcp_win' + str(idx) in k:
            octets = example[k]
            print('tcp_win: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].window = (octets[0] << 8) + octets[1]
        elif 'tcp_urg_ptr' + str(idx) in k:
            octets = example[k]
            print('tcp_urg_ptr: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].urgptr = (octets[0] << 8) + octets[1]

    #ls(pkt)
    #pkt.show()
    #pkt.show2()
    #wireshark(pkt)
    #hexdump(pkt)
    #send(pkt)


def probe_s2e(packets, sym_pkt_num=1, payload_len=0, bad_checksum=False, tcp_opt_timestamp=False, tcp_opt_md5=False):
    disable_other_packets()

    #print(packets)

    client_port = random.randint(10000,60000)

    # client initial sequence number
    #client_isn = random.getrandbits(32)
    client_isn = 0xdeadbeef
    # server initial sequence number
    server_isn = 0

    args = {}
    args['client_isn'] = client_isn

    # send pre packets
    i = 0
    for packet in packets:
        i += 1
        print("---------Pre-packet #%d---------" % i)

        # solve the constraints
        example = solve_constraints(packet['constraints'], args)

        payload = '\xff' * payload_len
        if bad_checksum:
            pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, chksum=0xffff, options=tcp_opts)/Raw(load=payload)
        else:
            pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, options=tcp_opts)/Raw(load=payload)

        update_pkt_with_example(pkt, example, i)
        pkt['IP'].ttl = 163 # to bypass the iptables rule
    
        hexdump(pkt)
        reply_pkt = sr1(pkt, timeout=3)

        if reply_pkt:
            hexdump(reply_pkt)
            if TCP in reply_pkt: # update isn_server with received reply_pkt
                if i == 1:
                    server_isn = reply_pkt['TCP'].seq
                    args['server_isn'] = server_isn

        sleep(0.2)

    if sym_pkt_num:
        #for i in range(sym_pkt_num):
        i = 0
        while True:
            i += 1
            print("---------Sending symbolic packet #%d---------" % i)
            tcp_opts = []
            if tcp_opt_timestamp:
                tcp_opts.append(('Timestamp', (0, 0)))
            if tcp_opt_md5:
                tcp_opts.append((19, '\xff' * 16))
            if tcp_opt_timestamp ^ tcp_opt_md5:
                tcp_opts.append(('NOP', None))
                tcp_opts.append(('NOP', None))

            payload = '\xff' * payload_len
            if bad_checksum:
                pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, seq=client_isn, ack=server_isn, chksum=0xffff, options=tcp_opts)/Raw(load=payload)
            else:
                pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, seq=client_isn, ack=server_isn, options=tcp_opts)/Raw(load=payload)

            pkt['IP'].ttl = 163 # to bypass the iptables rule
            send(pkt)
            time.sleep(0.1)
    
    raw_input("Press ENTER to continue...")

    enable_other_packets()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Probe S2E with packets generated by symbolic execution.')
    parser.add_argument('-f', dest='pkt_file', type=argparse.FileType('r'), help='concrete packet file')
    parser.add_argument('-s', dest='sym_pkt_num', type=int, default=1, help='number of symbolic packets to send')
    parser.add_argument('-p', dest='payload_len', type=int, default=0, help='TCP payload length (because header len is symbolic, payload may be counted as optional header')
    parser.add_argument('--ts', dest='tcp_opt_timestamp', default=False, action='store_true', help='Send packet with TCP option timestamp')
    parser.add_argument('--md5', dest='tcp_opt_md5', default=False, action='store_true', help='Send packet with TCP option MD5')
    parser.add_argument('-b', dest='bad_checksum', default=False, action='store_true', help='TCP payload length (because header len is symbolic, payload may be counted as optional header')
    args = parser.parse_args()

    all_entries = []
    
    if args.pkt_file:
        for line in args.pkt_file:
            all_entries.append(eval(line))

    #print(all_entries)

    if all_entries:
        i = 0
        for entry in all_entries:
            i += 1
            if i < START_FROM:
                continue
            probe_s2e(entry['test_cases'], args.sym_pkt_num, args.payload_len, args.bad_checksum, args.tcp_opt_timestamp, args.tcp_opt_md5)
    else:
        probe_s2e([], args.sym_pkt_num, args.payload_len, args.bad_checksum, args.tcp_opt_timestamp, args.tcp_opt_md5)
    
