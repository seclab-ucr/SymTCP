#!/usr/bin/env python

import datetime
import errno
import logging
import os
import pwd
import random
import signal
import subprocess
import sys
import time

from time import sleep

from scapy.all import sr1, TCP, IP, Raw, hexdump, sr, send, conf, L3RawSocket, rdpcap, Scapy_Exception
from scapy_http.http import HTTPResponse

from s2e_utils import *

# a hotfix to scapy TCP answer function
def myanswers(self, other):
    if not isinstance(other, TCP):
        return 0
    # RST packets don't get answers
    if other.flags.R:
        return 0
    # We do not support the four-way handshakes with the SYN+ACK
    # answer split in two packets (one ACK and one SYN): in that
    # case the ACK will be seen as an answer, but not the SYN.
    if self.flags.S:
        # SYN packets without ACK are not answers
        if not self.flags.A:
            return 0
        # SYN+ACK packets answer SYN packets
        if not other.flags.S:
            return 0
    if conf.checkIPsrc:
        if not ((self.sport == other.dport) and
                (self.dport == other.sport)):
            return 0
    # Do not check ack value for SYN packets without ACK
    #if not (other.flags.S and not other.flags.A) \
    #   and abs(other.ack - self.seq) > 2:
    #    return 0
    # Do not check ack value for RST packets without ACK
    if self.flags.R and not self.flags.A:
        return 1
    #if abs(other.seq - self.ack) > 2 + len(other.payload):
    #    return 0
    return 1

TCP.answers = myanswers

from z3 import *

set_param('model_compress', False)

logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S')

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

#consoleHandler = logging.StreamHandler()
#logger.addHandler(consoleHandler)
fileHandler = logging.FileHandler("probe_dpi.log", mode='w')
logger.addHandler(fileHandler)


MAX_INT = 9999999
START_FROM = 1
END_BY = MAX_INT

# time wait for server's reply
# for localhost use a small value such as 0.5s
# for remote host use a larger value such as 3s
TIME_WAIT_SERVER_ACK = 2
# wait additional 0.5s between packets
INTERVAL_BETWEEN_PACKET = 0.5

# Because the GFW blocks a 3-tuple (client IP, server IP, server Port) for 90 seconds
# We shouldn't use the same server again within 90 seconds
GFW_TIME_INTERVAL = 100
# Wait 3s after sending sensitive keyword for any RST packets
GFW_TIME_WAIT_RST = 3

LOCAL_TIME_INTERVAL = 0

PROJECT_DIR = "/home/alan/Work/s2e/s2e/projects/tcp"

PCAP_DIR = "./pcaps"

APACHE_LOG_PATH = "/var/log/apache2/"
SNORT_LOG_PATH = "/var/log/snort/"
BRO_LOG_PATH = "."
NETFILTER_LOG_PATH = "../logs"

apache_log_file_name = None
snort_log_file_name = None
bro_log_file_name = None
netfilter_log_file_name = None


SYN = 0x02
RST = 0x04
ACK = 0x10
FIN = 0x01

TCP_NO_SOCK = 0
TCP_ESTABLISHED = 1
TCP_CLOSE_WAIT = 8
TCP_LISTEN = 10
TCP_NEW_SYN_RECV = 12
TCP_SYN_RECV = 3

TCP_FLAGS_LST = {
    'SYN': SYN,
    'RST': RST,
    'ACK': ACK,
    'FIN': FIN,
    'RSTACK': RST | ACK,
    'FINACK': FIN | ACK
}

# SERVER_IP = '183.131.178.75'
# #SERVER_IP = '127.0.0.1'
# SERVER_PORT = 80
# #SERVER_PORT = 5555
SERVER_IP = '127.0.0.1'
#SERVER_IP = '172.20.0.2'
SERVER_PORT = 80
#SERVER_PORT = 5555

conf.L3socket=L3RawSocket

#HTTP_REQ = 'GET /search.php?keyword=ultrasurf HTTP/1.1\r\nHost: www.whatever.com\r\n\r\n'
HTTP_REQ_PREFIX = 'GET /'
HTTP_REQ_SUFFIX = '# HTTP/1.1\r\nHost: local_test_host\r\n\r\n'

BAD_KEYWORD = 'ultrasurf'

# error code
ERR_NO_SYNACK = 1
ERR_UNSOLVABLE = 2
ERR_NO_PCAP = 3
ERR_BAD_PCAP = 4
ERR_UNSOLVABLE2 = 5


server_list = []

dump_pcaps = False
tcpdump_interface = 'any'

args = None

MOD32 = 2**32

params = {}

def add(a, b):
    return (a + b) % MOD32

def sub(a, b):
	return (a - b) % MOD32

def before(a, b):
    if abs(a - b) > 2**31:
        if a < b:
            return False
        else:
            return True
    else:
        if a < b:
            return True
        else:
            return False

def after(a, b):
    return before(b, a)

def check_log_files():
    global apache_log_file_name, snort_log_file_name, bro_log_file_name, netfilter_log_file_name

    apache_log_file_name = os.path.join(APACHE_LOG_PATH, 'access.log')
    logger.info("Apache log file: %s" % apache_log_file_name)
    assert os.path.isfile(apache_log_file_name), "Cannot find apache log."

    files = glob.glob(SNORT_LOG_PATH + '/snort.*')
    assert files, "Cannot find snort log."
    snort_log_file_name = max(files, key=os.path.getctime)
    logger.info("Snort log file: %s" % snort_log_file_name)

    bro_log_file_name = os.path.join(BRO_LOG_PATH, 'notice.log')
    logger.info("Bro log file: %s" % bro_log_file_name)
    # bro log is generated after detection of a bad keyword
    #assert os.path.isfile(bro_log_file_name), "Cannot find bro log."

    files = glob.glob(NETFILTER_LOG_PATH + '/netfilter.pcap.*')
    assert files, "Cannot find netfilter log."
    netfilter_log_file_name = max(files, key=os.path.getctime)
    logger.info("Netfilter log file: %s" % netfilter_log_file_name)

def int2hexarr(num):
    v = []
    for i in range(4):
        v.append(num % 256)
        num /= 256
    return v
    
def dump(pkt):
    if IP not in pkt or TCP not in pkt: 
        return
    logger.info("%s:%d -> %s:%d" % (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport))
    logger.info("SEQ: %08x" % pkt[TCP].seq)
    logger.info("ACK: %08x" % pkt[TCP].ack)
    logger.info("Data offset: %d" % (pkt[TCP].dataofs * 4))
    logger.info("TCP flags: %s" % (pkt[TCP].flags or 'None'))
    logger.info("Window: %d" % (pkt[TCP].window))
    logger.info("Checksum: %04x" % (pkt[TCP].chksum or 0))
    logger.info("Urgent pointer: %04x" % (pkt[TCP].urgptr or 0))

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    enable_other_packets()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def exception_handler(exc_type, exc_value, exc_traceback):
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
    enable_other_packets()

sys.excepthook = exception_handler

def demote(user_uid, user_gid):
    def result():
        os.setgid(user_gid)
        os.setuid(user_uid)
    return result

def disable_other_packets():
    os.system("iptables -t raw -A OUTPUT -p tcp --dport %d -m ttl ! --ttl-eq 163 -j DROP" % SERVER_PORT)

def enable_other_packets():
    os.system("iptables -t raw -D OUTPUT -p tcp --dport %d -m ttl ! --ttl-eq 163 -j DROP" % SERVER_PORT)

def load_server_list(fname):
    f = open(fname, 'r')
    for line in f:
        line = line.strip()
        if line:
            server_ip = line
            server_list.append([server_ip, 0])
    f.close()

def pick_a_server():
    if args.gfw:
        assert server_list
        time_interval = GFW_TIME_INTERVAL
    else:
        if not server_list:
            return None
        time_interval = LOCAL_TIME_INTERVAL

    server_ip, ts = server_list.pop(0)
    now = time.time()
    if now - ts < time_interval:
        logger.info("Server is not ready yet. Sleeping for %d seconds..." % (time_interval + ts - now))
        time.sleep(time_interval + ts - now)
    ts = time.time()
    server_list.append([server_ip, ts])

    return server_ip

def check_gfw_rst(packets):
    rst_ack_cnt = 0
    for packet in packets:
        if packet['TCP'].flags == RST:
            if packet['IP'].flags == 0 and packet['TCP'].window != 0:
                recved_gfw_type1_rst = True
        elif packet['TCP'].flags == RST | ACK:
            rst_ack_cnt += 1
    # since we only send one data packet, if we received more than 1 RST/ACK, then they should be from the GFW
    if rst_ack_cnt > 1:
        recved_gfw_type2_rst = True

client_port = random.randint(10000, 40000)

def get_next_client_port():
    global client_port
    client_port += 1
    if client_port > 60000:
        client_port = 10000
    return client_port

def generate_constraint_str(varname, val, size):
    constraint = "(assert (and"
    for i in range(size):
        constraint += " (= (select {0} (_ bv{1} 32) ) #x{2:02x})".format(varname, i, val[i])
    constraint += "))"
    return constraint

def get_value_from_model(m, d, size):
    val = [0] * size
    if is_K(m[d]):
        for i in range(size):
            if i >= m[d].num_args():
                break
            val[i] = m[d].arg(i).as_long()
    elif isinstance(m[d], FuncInterp):
        for i in range(size):
            if i >= m[d].num_entries():
                break
            e = m[d].entry(i)
            assert e.num_args() == 1
            val[e.arg_value(0).as_long()] = e.value().as_long()
    return val

def extract_example_from_model(m):
    example = {}
    for d in m:
        k = str(d)
        if 'tcp_seq_num' in k:
            field_val = get_value_from_model(m, d, 4)
            example[k] = field_val
        elif 'tcp_ack_num' in k:
            field_val = get_value_from_model(m, d, 4)
            example[k] = field_val
        elif 'tcp_doff_reserved_flags' in k:
            field_val = get_value_from_model(m, d, 1)
            example[k] = field_val
        elif 'tcp_flags' in k:
            field_val = get_value_from_model(m, d, 1)
            example[k] = field_val
        elif 'tcp_win' in k:
            field_val = get_value_from_model(m, d, 2)
            example[k] = field_val
        elif 'tcp_urg_ptr' in k:
            field_val = get_value_from_model(m, d, 2)
            example[k] = field_val
        elif 'tcp_options' in k:
            field_val = get_value_from_model(m, d, args.payload_len)
            example[k] = field_val
    return example

def save_example_to_params(example, params, cur_packet_idx):
    for k, v in example.iteritems():
        packet_idx, _ = get_packet_idx(k)
        if 0 < packet_idx <= cur_packet_idx:
            varname_short = k.split('_', 1)[1].rsplit('_', 1)[0]
            params[varname_short] = bytes2int_be(v)

def solve_constraints(constraints, params, cur_packet_idx):
    logger.info("Solving constraints...")
    logger.debug("params: %s" % params)
    seq2_gt_seq1 = False
    bnums = re.findall('\?B(\d+)', constraints)
    bmax = max([int(num) for num in bnums])

    constraints = constraints.split('\n')
    constraints_new = []
    varnames = {}

    #set_param('smt.phase_selection', 5)
    for line in constraints:
        if line and line != '(check-sat)' and line != '(exit)':
            constraints_new.append(line)
        if line.startswith("(declare-"):
            varname = line.split()[1]
            if re.match('v\d+_.*_\d+', varname):
                varname_short = varname.split('_', 1)[1].rsplit('_', 1)[0]
                varnames[varname_short] = varname

    # declare variables if not present
    for p in params:
        if p not in varnames:
            logger.debug("Declaring %s..." % p)
            # all variable declaration are the same
            constraint = "(declare-fun %s () (Array (_ BitVec 32) (_ BitVec 8) ) )" % p
            #logger.debug("New declaration: %s" % constraint)
            constraints_new.append(constraint)
            varnames[p] = p

    # add constraints
    for p in params:
        if p.startswith(('tcp_seq_num', 'tcp_ack_num')):
            # tcp_seq_num/tcp_ack_num is network-order (big-endian) because we symbolized a packet field
            v = int2bytes_be(params[p], 4)
            constraint = generate_constraint_str(varnames[p], v, 4)
            constraints_new.append(constraint)
        elif p == 'tcp_svr_isn':
            # server ISN is host-order (little-endian) because we symbolized a local variable
            v = int2bytes_le(params[p], 4)
            constraint = generate_constraint_str(varnames[p], v, 4)
            constraints_new.append(constraint)
        elif p.startswith('tcp_doff_reserved_flags'):
            v = int2bytes_be(params[p], 1)
            constraint = generate_constraint_str(varnames[p], v, 1)
            constraints_new.append(constraint)
        elif p.startswith('tcp_flags'):
            v = int2bytes_be(params[p], 1)
            constraint = generate_constraint_str(varnames[p], v, 1)
            constraints_new.append(constraint)
        elif p.startswith('tcp_win'):
            v = int2bytes_be(params[p], 2)
            constraint = generate_constraint_str(varnames[p], v, 2)
            constraints_new.append(constraint)
        elif p.startswith('tcp_urg_ptr'):
            v = int2bytes_be(params[p], 2)
            constraint = generate_constraint_str(varnames[p], v, 2)
            constraints_new.append(constraint)
        elif p.startswith('tcp_options'):
            v = int2bytes_be(params[p], args.payload_len)
            constraint = generate_constraint_str(varnames[p], v, args.payload_len)
            constraints_new.append(constraint)

    # try to make tcp_seq_num2 larger than tcp_seq_num1
    if seq2_gt_seq1:
        constraints_new2 = constraints_new[:]
        logger.debug("Trying to add constraint: tcp_seq_num2 > tcp_seq_num1")
        if 'tcp_seq_num1' not in varnames:
            logger.debug("Declaring tcp_seq_num1...")
            constraint = "(declare-fun tcp_seq_num1 () (Array (_ BitVec 32) (_ BitVec 8) ) )"
            #logger.debug("New declaration: %s" % constraint)
            constraints_new2.append(constraint)
            varnames['tcp_seq_num1'] = 'tcp_seq_num1'
        if 'tcp_seq_num2' not in varnames:
            logger.debug("Declaring tcp_seq_num2...")
            constraint = "(declare-fun tcp_seq_num2 () (Array (_ BitVec 32) (_ BitVec 8) ) )"
            constraints_new2.append(constraint)
            #logger.debug("New declaration: %s" % constraint)
            varnames['tcp_seq_num2'] = 'tcp_seq_num2'
        constraint = "(assert (let ( (?B{0:d} ((_ zero_extend 32)  ((_ extract 31  0)  (bvlshr ((_ zero_extend 32)  ((_ extract 31  0)  (bvsub  ((_ zero_extend 32) (concat  (select {1} (_ bv0 32) ) (concat  (select {1} (_ bv1 32) ) (concat  (select {1} (_ bv2 32) ) (select {1} (_ bv3 32) ) ) ) ) ) ((_ zero_extend 32) (concat  (select  {2} (_ bv0 32) ) (concat  (select {2} (_ bv1 32) ) (concat  (select {2} (_ bv2 32) ) (select {2} (_ bv3 32) ) ) ) ) ) ) ) ) (_ bv31 64) ) ) ) ) ) (=  false (=  (_ bv0 64) (bvand  (bvand  ?B{0:d} ?B{0:d} ) (_ bv255 64) ) ) ) ) )".format(bmax, varnames['tcp_seq_num1'], varnames['tcp_seq_num2'])
        #logger.debug("New constraint: %s" % constraint)
        constraints_new2.append(constraint)
        constraints = '\n'.join(constraints_new2)
        # solve
        s = Solver()
        F = parse_smt2_string(constraints)
        #logger.debug(F.sexpr())
        s.add(F)
        res = s.check()
        #logger.debug(res)
        if res == sat:
            m = s.model()
            #logger.debug(m)
            example = extract_example_from_model(m)
            logger.info("---------Solved Example---------")
            logger.info(example)
            logger.info("---------Example End---------")
            seq_num1 = bytes2int_be(example[varnames['tcp_seq_numm1']])
            seq_num2 = bytes2int_be(example[varnames['tcp_seq_numm2']])
            #logger.debug("seq_num1: 0x%08x" % seq_num1)
            #logger.debug("seq_num2: 0x%08x" % seq_num2)
            assert(before(seq_num1, seq_num2))
            save_example_to_params(example, params, cur_packet_idx)
            return example
        logger.debug("Cannot make seq_num1 > seq_num2.")

    constraints = '\n'.join(constraints_new)
    #logger.debug(constraints)

    s = Solver()
    F = parse_smt2_string(constraints)
    #logger.debug(F.sexpr())
    s.add(F)
    res = s.check()
    #logger.debug(res)
    if res == sat:
        m = s.model()
        #logger.debug(m)
        example = extract_example_from_model(m)
        logger.info("---------Solved Example---------")
        logger.info(example)
        logger.info("---------Example End---------")
        save_example_to_params(example, params, cur_packet_idx)
        return example
    else:
        logger.debug("####### Cannot solve constraint! #######")

    return None

# relax the constraints in params in the order given in priority list
def relax_constraints(params, priority_list):
    for k in priority_list:
        if k in params:
            del params[k]
            logger.debug("Removed constraint on %s." % k)
            return True
    return False

# update the packet with concrete example of packet with index `idx`
def update_tcp_header_with_example(pkt, example, idx):
    tcp_options_var = None
    for k, v in example.iteritems():
        if 'tcp_header' + str(idx) in k:
            octets = example[k]
            logger.info('tcp_header: ' + ' '.join([ ('%02X' % o) for o in octets ]))
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
            logger.info('tcp_seq_num: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].seq = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
        elif 'tcp_ack_num' + str(idx) in k:
            octets = example[k]
            logger.info('tcp_ack_num: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].ack = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
        elif 'tcp_doff_reserved_flags' + str(idx) in k:
            octets = example[k]
            logger.info('tcp_doff_reserved_flags: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].dataofs = octets[0] >> 4
            pkt[TCP].reserved = octets[0] & 0xf
        elif 'tcp_flags' + str(idx) in k:
            octets = example[k]
            logger.info('tcp_flags: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].flags = octets[0]
        elif 'tcp_win' + str(idx) in k:
            octets = example[k]
            logger.info('tcp_win: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].window = (octets[0] << 8) + octets[1]
        elif 'tcp_urg_ptr' + str(idx) in k:
            octets = example[k]
            logger.info('tcp_urg_ptr: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].urgptr = (octets[0] << 8) + octets[1]
        elif 'tcp_options' + str(idx) in k:
            tcp_options_var = k
            # tcp options has to be updated after data offset, since we need to use it to calculate the payload

    if tcp_options_var:
        octets = example[tcp_options_var]
        logger.info('tcp_options: ' + ' '.join([ ('%02X' % o) for o in octets ]))
        # prepend it to the payload
        data_offset = pkt[TCP].dataofs * 4
        opt_len = data_offset - 20
        pkt[TCP].payload.load = ''.join([ chr(o) for o in octets[:opt_len] ]) + pkt[TCP].payload.load[opt_len:]

    #ls(pkt)
    #pkt.show()
    #pkt.show2()
    #wireshark(pkt)
    #hexdump(pkt)
    #send(pkt)

def send_3way_handshake_and_data(server_ip, client_port, example_id, packet_num):
    # client initial sequence number
    client_isn = random.getrandbits(32)
    # server initial sequence number
    server_isn = 0

    syn_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='S', seq=client_isn)
    syn_pkt['IP'].ttl = 163 # to bypass the iptables rule

    #hexdump(syn_pkt)
    reply_pkt = sr1(syn_pkt, timeout=3) 
    logger.info("Sent SYN packet...")
    client_seq = client_isn + 1

    if reply_pkt:
        #hexdump(reply_pkt)
        if TCP in reply_pkt and reply_pkt['TCP'].flags & (SYN | ACK) == SYN | ACK:
            logger.info("Received SYN/ACK packet...")
            # update isn_server with received reply_pkt
            server_isn = reply_pkt['TCP'].seq
            server_seq = server_isn + 1
        else:
            logger.warn("Received non SYN/ACK packet.")
            return
    else:
        logger.warn("No SYN/ACK packet received.")
        return

    ack_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_seq, ack=server_seq)
    ack_pkt['IP'].ttl = 163 # to bypass the iptables rule

    #hexdump(ack_pkt)
    send(ack_pkt) 
    logger.info("Sent ACK packet...")

    payload = "GET /" + BAD_KEYWORD + '#' + str(example_id) + '#' + str(packet_num) + HTTP_REQ_SUFFIX
    data_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_seq, ack=server_seq)/Raw(load=payload)
    data_pkt['IP'].ttl = 163 # to bypass the iptables rule

    #hexdump(data_pkt)
    sleep(0.2)
    send(data_pkt)
    logger.info("Sent Data packet...")

    if args.gfw:
        logger.info("Waiting %ds for server and GFW response..." % GFW_TIME_WAIT_RST)
        sleep(GFW_TIME_WAIT_RST)

def send_ack_and_data(server_ip, client_port, client_seq, server_seq, client_isn, example_id, packet_num):
    ack_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_seq, ack=server_seq)
    ack_pkt['IP'].ttl = 163 # to bypass the iptables rule

    #hexdump(ack_pkt)
    send(ack_pkt) 
    logger.info("Sent ACK packet...")

    if client_seq < client_isn: 
        # SEQ number wraparound
        offset = client_seq + 2**32 - client_isn - 1
    else:
        offset = client_seq - client_isn - 1
    if offset < 0: 
        offset = 0
    if offset >= 5:
        payload = BAD_KEYWORD + '#' + str(example_id) + '#' + str(packet_num) + HTTP_REQ_SUFFIX
    else:
        payload = "GET /" + BAD_KEYWORD + '#' + str(example_id) + '#' + str(packet_num) + HTTP_REQ_SUFFIX
        payload = payload[offset:]
    data_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_seq, ack=server_seq)/Raw(load=payload)
    data_pkt['IP'].ttl = 163 # to bypass the iptables rule

    #hexdump(data_pkt)
    sleep(0.2)
    send(data_pkt)
    logger.info("Sent Data packet...")

    if args.gfw:
        logger.info("Waiting %ds for server and GFW response..." % GFW_TIME_WAIT_RST)
        sleep(GFW_TIME_WAIT_RST)

def send_data(server_ip, client_port, client_seq, server_seq, client_isn, example_id, packet_num):
    if client_seq < client_isn: 
        # SEQ number wraparound
        offset = client_seq + 2**32 - client_isn - 1
    else:
        offset = client_seq - client_isn - 1
    if offset < 0: 
        offset = 0
    if offset >= 5:
        payload = BAD_KEYWORD + '#' + str(example_id) + '#' + str(packet_num) + HTTP_REQ_SUFFIX
    else:
        payload = "GET /" + BAD_KEYWORD + '#' + str(example_id) + '#' + str(packet_num) + HTTP_REQ_SUFFIX
        payload = payload[offset:]
    data_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_seq, ack=server_seq)/Raw(load=payload)
    data_pkt['IP'].ttl = 163 # to bypass the iptables rule

    #hexdump(data_pkt)
    sleep(0.2)
    send(data_pkt)
    logger.info("Sent Data packet...")

    if args.gfw:
        logger.info("Waiting %ds for server and GFW response..." % GFW_TIME_WAIT_RST)
        sleep(GFW_TIME_WAIT_RST)

def kill_process(p):
    sleep(1)
    p.terminate()
    os.system("pkill tcpdump")
    os.system("pkill tcpdump")
    os.system("pkill tcpdump")

def calculate_payload(example, pkt_idx, payload_len, client_isn):
    client_seq = client_isn
    data_offset = 0
    # get the client seq number and data offset from the example if there's any
    client_seq_var_name = 'tcp_seq_num' + str(pkt_idx)
    data_off_var_name = 'tcp_doff_reserved_flags' + str(pkt_idx)
    for k, v in example.iteritems():
        if client_seq_var_name in k:
            client_seq = (v[0] << 24) + (v[1] << 16) + (v[2] << 8) + v[3]
        if data_off_var_name in k:
            data_offset = (v[0] >> 4) * 4

    payload = ''
    if payload_len:
        if pkt_idx == 1:
            payload = '\xff' * (data_offset - 20) + HTTP_REQ_PREFIX
        else:
            # calculate the payload offset using client seq number
            padding = ''
            if after(client_seq, client_isn):
                offset = client_seq - client_isn - 1
                if offset < 0:
                    offset += 2**32
            else:
                offset = client_seq - client_isn - 1
                if offset > 0:
                    offset -= 2**32
                padding = 'A' * min(-offset, 100)   # we pad maximum 100 bytes
                offset = 0
            payload = '\xff' * (data_offset - 20) + padding + HTTP_REQ_PREFIX[offset:] 
        payload = payload[:payload_len]
        if len(payload) < payload_len:
            payload += 'A' * (payload_len - len(payload))

    return payload

def send_probing_packets(test_case, server_ip, packet_num, is_evasion_pkt, example_id, tcp_flags, payload_len, bad_checksum_case):
    #logger.debug(test_case)

    client_port = get_next_client_port()

    # client initial sequence number
    client_isn = random.getrandbits(32)
    # server initial sequence number
    server_isn = 0

    params = {}
    #params['tcp_seq_num1'] = client_isn

    # initialize SEQ and ACK
    client_seq = client_isn
    client_ack = 0
    server_seq_recved = False
    server_ack_recved = False
    server_seq = 0
    server_ack = 0

    example = solve_constraints(test_case['constraints'], params, 1)
    if not example:
        logger.warn("Failed to solve constraints.")
        return -ERR_UNSOLVABLE

    for k, v in example.iteritems():
        if 'tcp_seq_num1' in k:
            client_seq = bytes2int_be(v)
            break

    # if constraint solver has generated a client ISN, then use it, otherwise use our own
    if client_seq != client_isn:
        # constraint solve has generated a new client ISN
        client_isn = client_seq

    for i in range(1, packet_num + 1):
        logger.info("---------Packet #%d---------" % i)

        if i == packet_num:
            # try to constrain the TCP flags and SEQ and ACK number with valid values for the insertion/evasion packet,
            # to make it more/less likely to be accepted by the DPI
            logger.debug("Trying to constrain the %s packet (SEQ, ACK, flags)..." % ("evasion" if is_evasion_pkt else "insertion"))
            if packet_num > 1 and server_ack_recved:
                if is_evasion_pkt:
                    params['tcp_seq_num' + str(i)] = server_ack + 10
                else:
                    params['tcp_seq_num' + str(i)] = server_ack
            if packet_num > 1 and server_seq_recved:
                if is_evasion_pkt:
                    params['tcp_ack_num' + str(i)] = server_seq + 10
                else:
                    params['tcp_ack_num' + str(i)] = server_seq
            if tcp_flags:
                params['tcp_flags' + str(i)] = tcp_flags
            example = solve_constraints(test_case['constraints'], params, i)
            if not example:
                logger.debug("Seems we are overconstraining, we need to relax the constraint...")
                ok = False
                while relax_constraints(params, ['tcp_ack_num' + str(packet_num), 'tcp_seq_num' + str(packet_num)]):
                    example = solve_constraints(test_case['constraints'], params, i)
                    if example:
                        ok = True
                        break
                    else:
                        logger.debug("Still not working, relaxing more constriant...")
                if not ok: 
                    logger.debug("No more constraints to relax, giving up...")
                    logger.warn("Failed to solve constraints.")
                    return -ERR_UNSOLVABLE2

        payload = ''
        if payload_len:
            payload = calculate_payload(example, i, payload_len, client_isn)

        if i == packet_num and bad_checksum_case:
            pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='S', seq=client_seq, chksum=0xffff)/Raw(load=payload)
        else:
            pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='S', seq=client_seq)/Raw(load=payload)
        update_tcp_header_with_example(pkt, example, i)
        logger.info("payload: %s" % ' '.join([ "%02x" % ord(c) for c in pkt[TCP].payload.load]))
        pkt[IP].ttl = 163 # to bypass the iptables rule

        #hexdump(pkt)
        #dump(pkt)
        if i == packet_num:
            logger.info('Flags: %s' % (pkt[TCP].flags or 'None'))
            if is_evasion_pkt:
                logger.info("Sending evasion packet...")
            else:
                logger.info("Sending insertion packet...")
        else:
            params, logger.info("Sending packet...")
        reply_pkt = sr1(pkt, timeout=TIME_WAIT_SERVER_ACK) 
        if reply_pkt:
            #hexdump(reply_pkt)
            if TCP in reply_pkt:
                server_seq_recved = True
                server_seq = reply_pkt[TCP].seq
                if reply_pkt[TCP].flags & ACK == ACK:
                    server_ack_recved = True
                    server_ack = reply_pkt[TCP].ack

                if reply_pkt[TCP].flags & (SYN | ACK) == SYN | ACK:
                    logger.info("Received SYN/ACK packet from server.")
                    # received a SYN/ACK packet
                    # update server_isn with sequence number in SYN/ACK
                    # assuming the firewall doesn't send deceptive SYN/ACK 
                    server_isn = reply_pkt[TCP].seq
                    params['tcp_svr_isn'] = server_isn
                    server_seq = server_isn + 1

                    example = solve_constraints(test_case['constraints'], params, 2)
                    if not example:
                        logger.warn("Failed to solve constraints.")
                        return -ERR_UNSOLVABLE
            else:
                logger.warn("Received non TCP packet.")

        if i == 1 and 'tcp_svr_isn' not in params:
            # didn't receive SYN/ACK?
            if is_evasion_pkt:
                # for evasion packet, it should always be accepted
                logger.warn("Didn't receive SYN/ACK packet after sending the first packet.")
                return -ERR_NO_SYNACK
            else:
                # for insertion packet, if it has more than 1 packet, then the first one should be accepted.
                if packet_num > 1:
                    logger.warn("Didn't receive SYN/ACK packet after sending the first packet.")
                    return -ERR_NO_SYNACK

        #sleep(INTERVAL_BETWEEN_PACKET)

    # send follow-up packets
    sk_state = test_case['sk_state'][packet_num]
    if sk_state == 0 and packet_num > 1:
        sk_state = test_case['sk_state'][packet_num-1]
    if sk_state == TCP_NO_SOCK:
        logger.info("*******************************")
        logger.info("* Current stat is TCP_NO_SOCK *")
        logger.info("*******************************")
        send_3way_handshake_and_data(server_ip, client_port, example_id, packet_num)
    elif sk_state == TCP_LISTEN:
        logger.info("******************************")
        logger.info("* Current stat is TCP_LISTEN *")
        logger.info("******************************")
        send_3way_handshake_and_data(server_ip, client_port, example_id, packet_num)
    elif sk_state == TCP_NEW_SYN_RECV:
        logger.info("************************************")
        logger.info("* Current stat is TCP_NEW_SYN_RECV *")
        logger.info("************************************")
        send_ack_and_data(server_ip, client_port, server_ack, server_seq, client_isn, example_id, packet_num)
    elif sk_state == TCP_SYN_RECV:
        logger.info("************************************")
        logger.info("* Current stat is TCP_SYN_RECV *")
        logger.info("************************************")
        send_ack_and_data(server_ip, client_port, server_ack, server_seq, client_isn, example_id, packet_num)
    elif sk_state == TCP_ESTABLISHED:
        logger.info("***********************************")
        logger.info("* Current stat is TCP_ESTABLISHED *")
        logger.info("***********************************")
        send_data(server_ip, client_port, server_ack, server_seq, client_isn, example_id, packet_num)
    elif sk_state  == TCP_CLOSE_WAIT:
        # server may still be able to receive data in TCP_CLOSE_WAIT state
        logger.info("***********************************")
        logger.info("* Current stat is TCP_CLOSE_WAIT *")
        logger.info("***********************************")
        send_data(server_ip, client_port, server_ack, server_seq, client_isn, example_id, packet_num)
    else:
        logger.warn("Unexpected sk_state: %d" % sk_state)
    sleep(1)

    return 0


def probe_dpi(test_case, server_ip, packet_num, is_evasion_pkt, example_id, tcp_flags=None, tcp_flags_name=None, payload_len=0, bad_checksum_case=False):
    disable_other_packets()

    if dump_pcaps:
        if not os.path.exists(PCAP_DIR):
            os.mkdir(PCAP_DIR)
        if tcp_flags and tcp_flags_name:
            pcap_file = '%s/packet_dump_%s_%s_%s_%s_%d.pcap' % (PCAP_DIR, test_case['state_id'], server_ip, datetime.datetime.now().strftime("%Y%m%d_%H%M%S"), tcp_flags_name, packet_num)
        else:
            pcap_file = '%s/packet_dump_%s_%s_%s_%d.pcap' % (PCAP_DIR, test_case['state_id'], server_ip, datetime.datetime.now().strftime("%Y%m%d_%H%M%S"), packet_num)
        logger.info("Recoding by pcap filename: " + pcap_file)
        tcpdump_p = subprocess.Popen(['tcpdump', '-i', tcpdump_interface, '-w', pcap_file, 'host %s and tcp port %d' % (server_ip, SERVER_PORT)])
        sleep(1)

    ret = send_probing_packets(test_case, server_ip, packet_num, is_evasion_pkt, example_id, tcp_flags, payload_len, bad_checksum_case)

    retry = 0
    while ret == -ERR_NO_SYNACK or ret == -ERR_UNSOLVABLE:
        logger.debug("Retrying...")
        retry += 1
        ret = send_probing_packets(test_case, server_ip, packet_num, is_evasion_pkt, example_id, tcp_flags, payload_len, bad_checksum_case)
        if retry >= 3:
            break

    if dump_pcaps:
        kill_process(tcpdump_p)
        #sleep(1)
        #tcpdump_p.terminate()
        #os.kill(os.getpgid(tcpdump_p.pid), signal.SIGTERM)
        #os.system("pkill tcpdump")
        #os.system("pkill tcpdump")
        #os.system("pkill tcpdump")

    enable_other_packets()

    #raw_input("Press ENTER to continue...")
    return ret


# find client port using 3-way handshake
def find_client_port(packets):
    client_ports = {}
    for packet in packets:
        if TCP in packet:
            if packet[TCP].dport == 80:
                if packet[TCP].flags & SYN == SYN:
                    # SYN packet
                    #print("SYN recved.")
                    if packet[TCP].sport not in client_ports:
                        client_ports[packet[TCP].sport] = 1
                if packet[TCP].flags & ACK == ACK:
                    # ACK packet
                    #print("ACK recved.")
                    if client_ports.get(packet[TCP].sport) == 2:
                        client_ports[packet[TCP].sport] = 3
                        # found
                        return packet[TCP].sport
            elif packet[TCP].sport == 80:
                if packet[TCP].flags & (SYN | ACK) == SYN | ACK:
                    # SYN/ACK packet
                    #print("SYN/ACK recved.")
                    if client_ports.get(packet[TCP].dport) == 1:
                        client_ports[packet[TCP].dport] = 2
        else:
            print('Non-TCP packet?!')
            print(packet.summary())

    return 0

def check_gfw_rst(packets):
    rst_ack_cnt = 0
    recved_gfw_type1_rst, recved_gfw_type2_rst = False, False
    for packet in packets:
        if not packet.haslayer(TCP):
            if args.debug:
                logger.warn("No TCP layer detected.")
            continue
        if packet['TCP'].flags == RST:
            if packet['IP'].flags == 0 and packet['TCP'].window != 0:
                recved_gfw_type1_rst = True
        elif packet['TCP'].flags == RST | ACK:
            rst_ack_cnt += 1
    # since we only send one data packet, if we received more than 1 RST/ACK, then they should be from the GFW
    if rst_ack_cnt > 1:
        recved_gfw_type2_rst = True
    return recved_gfw_type1_rst or recved_gfw_type2_rst

def check_server_response(packets):
    client_port = find_client_port(packets)
    for packet in packets:
        if packet.haslayer(HTTPResponse) and packet[TCP].dport == client_port:
            return True
    return False

def verify_gfw_result(example_id):
    logger.debug("===Verifying results of '%s'===" % example_id)
    result = { 'server': False, 'gfw': False }

    state_id_with_flags, packet_num = example_id.split('#')
    
    if state_id_with_flags.endswith(('SYN', 'RST', 'ACK', 'FIN', 'RSTACK', 'FINACK')):
        state_id, tcp_flags = state_id_with_flags.rsplit('_', 1)
        pcap_files = glob.glob(PCAP_DIR + "/packet_dump_%s_*_%s_%s.pcap" % (state_id, tcp_flags, packet_num))
        if len(pcap_files) != 1:
            logger.error("Found more than 1 pacp files: %s" % pcap_files)
        pcap_file = pcap_files[0]
    else:
        state_id = state_id_with_flags
        tcp_flags = ''
        pcap_files = glob.glob(PCAP_DIR + "/packet_dump_%s_*_%s.pcap" % (state_id, packet_num))
        pcap_file = ''
        for pf in pcap_files:
            parts = pf.split('/')[-1].split('_')
            if 'c' in state_id:
                # bad checksum case
                if len(parts) == 10:
                    pcap_file = pf
                    break
            else:
                if len(parts) == 7:
                    pcap_file = pf
                    break
        if not pcap_file:
            logger.error("Cannot find pcap file. %s" % pcap_files)
            return -ERR_NO_PCAP

    try:
        packets = rdpcap(pcap_file)
    except Scapy_Exception:
        logger.error("Bad pcap...")
        return -ERR_BAD_PCAP

    if check_server_response(packets):
        result['server'] = True
    logger.debug("Server received: %s" % result['server'])

    if check_gfw_rst(packets):
        result['gfw'] = True
    logger.debug("GFW detected: %s" % result['gfw'])

    return result

def verify_local_result(example_id):
    logger.debug("===Verifying results of '%s'===" % example_id)
    result = { 'apache': False, 'snort': False, 'bro': False, 'netfilter': False }

    state_id_with_flags, packet_num = example_id.split('#')
    
    if state_id_with_flags.endswith(('SYN', 'RST', 'ACK', 'FIN', 'RSTACK', 'FINACK')):
        state_id, tcp_flags = state_id_with_flags.rsplit('_', 1)
        pcap_files = glob.glob(PCAP_DIR + "/packet_dump_%s_*_%s_%s.pcap" % (state_id, tcp_flags, packet_num))
        if len(pcap_files) != 1:
            logger.error("Found more than 1 pacp files: %s" % pcap_files)
        pcap_file = pcap_files[0]
    else:
        state_id = state_id_with_flags
        tcp_flags = ''
        pcap_files = glob.glob(PCAP_DIR + "/packet_dump_%s_*_%s.pcap" % (state_id, packet_num))
        pcap_file = ''
        for pf in pcap_files:
            parts = pf.split('/')[-1].split('_')
            if 'c' in state_id:
                # bad checksum case
                if len(parts) == 10:
                    pcap_file = pf
                    break
            else:
                if len(parts) == 7:
                    pcap_file = pf
                    break
        if not pcap_file:
            logger.error("Cannot find pcap file. %s" % pcap_files)
            return -ERR_NO_PCAP

    try:
        packets = rdpcap(pcap_file)
    except Scapy_Exception:
        logger.error("Bad pcap...")
        return -ERR_BAD_PCAP

    if check_server_response(packets):
        result['apache'] = True
        logger.debug("Apache received: %s" % result['apache'])

    # bro log is generated after detection of a bad keyword
    if os.path.isfile(bro_log_file_name):
        f = open(bro_log_file_name, 'r')
        for line in f.readlines()[-10:]:
            if example_id in line:
                result['bro'] = True
                break
        f.close()
    logger.debug("Bro detected: %s" % result['bro'])

    f = open(snort_log_file_name, 'rb')
    f.seek(0, os.SEEK_END)
    size = f.tell()
    if size > 1024:
        size = 1024
    f.seek(-size, os.SEEK_END)
    content = f.read()
    if example_id in content:
        result['snort'] = True
    f.close()
    logger.debug("Snort detected: %s" % result['snort'])

    f = open(netfilter_log_file_name, 'rb')
    f.seek(0, os.SEEK_END)
    size = f.tell()
    if size > 1024:
        size = 1024
    f.seek(-size, os.SEEK_END)
    content = f.read()
    if example_id in content:
        result['netfilter'] = True
    f.close()
    logger.debug("Netfilter detected: %s" % result['netfilter'])

    return result

def verify_local_result2(example_id):
    logger.debug("===Verifying results of '%s'===" % example_id)
    result = { 'apache': False, 'snort': False, 'bro': False, 'netfilter': False }

    f = open(apache_log_file_name, 'r')
    for line in f.readlines()[-10:]:
        if example_id in line:
            result['apache'] = True
            break
    f.close()
    logger.debug("Apache received: %s" % result['apache'])

    # bro log is generated after detection of a bad keyword
    if os.path.isfile(bro_log_file_name):
        f = open(bro_log_file_name, 'r')
        for line in f.readlines()[-10:]:
            if example_id in line:
                result['bro'] = True
                break
        f.close()
    logger.debug("Bro detected: %s" % result['bro'])

    f = open(snort_log_file_name, 'rb')
    f.seek(0, os.SEEK_END)
    size = f.tell()
    if size > 1024:
        size = 1024
    f.seek(-size, os.SEEK_END)
    content = f.read()
    if example_id in content:
        result['snort'] = True
    f.close()
    logger.debug("Snort detected: %s" % result['snort'])

    f = open(netfilter_log_file_name, 'rb')
    f.seek(0, os.SEEK_END)
    size = f.tell()
    if size > 1024:
        size = 1024
    f.seek(-size, os.SEEK_END)
    content = f.read()
    if example_id in content:
        result['netfilter'] = True
    f.close()
    logger.debug("Netfilter detected: %s" % result['netfilter'])

    return result

def run_test_case(entry, packet_idx=None, tcp_flags=None):
    state_id = entry['state_id']

    tcp_flags_to_run = []

    if tcp_flags:
        # specified TCP flags
        tcp_flags_name = tcp_flags
        tcp_flags_hex = TCP_FLAGS_LST[tcp_flags_name]
        tcp_flags_to_run.append((str(state_id) + '_' + tcp_flags_name, tcp_flags_hex, tcp_flags_name))
    else:
        tcp_flags_to_run.append((str(state_id), None, None))
        if args.tcp_flags_fuzzing:
            for tcp_flags_name, tcp_flags_hex in TCP_FLAGS_LST.iteritems():
                tcp_flags_to_run.append((str(state_id) + '_' + tcp_flags_name, tcp_flags_hex, tcp_flags_name))

    packet_num = entry['packet_num']

    for j in range(1, packet_num + 1):
        if packet_idx and j != packet_idx:
            continue
        logger.info(">> Evaluating packet (%d/%d) <<" % (j, packet_num))
        succeeded = False
        if j not in entry['results']:
            entry['results'][j] = {}

        for state_id_with_flags, tcp_flags_hex, tcp_flags_name in tcp_flags_to_run:
            #logger.info("==================================================")
            #logger.info("== Evaluating test case %i with specific flags..." % i)
            #logger.info("==================================================")

            if tcp_flags_name is None:
                logger.info(">> Use original TCP flag <<")
            else:
                logger.info(">> Picked TCP flag %s <<" % tcp_flags_name)

            server_ip = pick_a_server()
            if not server_ip:
                server_ip = SERVER_IP

            is_evasion_pkt = j < packet_num or not entry['drop_points']
            if 'c' in entry['state_id'] and not is_evasion_pkt:
                bad_checksum_case = True
            else:
                bad_checksum_case = False
            ret = probe_dpi(entry, server_ip, j, is_evasion_pkt, state_id_with_flags, tcp_flags_hex, tcp_flags_name, args.payload_len, bad_checksum_case)

            if ret < 0:
                entry['results'][j][tcp_flags_name] = ret
            else:
                if args.gfw:
                    result = verify_gfw_result("%s#%d" % (state_id_with_flags, j))
                    if isinstance(result, dict):
                        if result['server'] and not result['gfw']:
                            # server received but GFW not detected
                            succeeded = True
                else:
                    result = verify_local_result("%s#%d" % (state_id_with_flags, j))
                    if isinstance(result, dict):
                        if result['apache'] and not result['snort'] and not result['bro'] and not result['netfilter']:
                            # apache received but all DPIs not detected
                            succeeded = True

                entry['results'][j][tcp_flags_name] = result

            if args.debug:
                raw_input("Press ENTER to continue...")

        if succeeded:
            logger.info("Already succeeded. No need to send later packets.")
            break


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Probe DPI with test cases generated from symbolic execution.')
    parser.add_argument('test_case_file', type=argparse.FileType('r'), help='test case file')
    parser.add_argument('-P', '--dump-pcaps', default=False, action='store_true', help='dump pcap files for each test case')
    parser.add_argument('-G', '--gfw', default=False, action='store_true', help='probing the gfw')
    parser.add_argument('-I', '--int', help='interface to listen on')
    parser.add_argument('-F', '--tcp-flags-fuzzing', action='store_true', help='switch of tcp flags fuzzing')
    parser.add_argument('--tcp-flags', type=str, help='Use specific TCP flags for testing')
    parser.add_argument('-D', '--debug', action='store_true', help='turn on debug mode')
    parser.add_argument('-p', dest='payload_len', type=int, default=0, help='TCP payload length (because header len is symbolic, payload may be counted as optional header')
    parser.add_argument('-N', dest='num_insts', default=1, type=int)
    parser.add_argument('-S', dest='split_id', default=0, type=int)
    parser.add_argument('-t', dest='test_case_idx', type=int, help='test case index')
    parser.add_argument('--packet-idx', type=int, help='packet index in the test case')
    parser.add_argument('--replay', type=argparse.FileType('r'), help='replay a list of successful cases')
    args = parser.parse_args()

    if args.gfw:
        load_server_list('server_list')
    else:
        load_server_list('server_list.local')
        check_log_files()

    if args.int:
        tcpdump_interface = args.int

    dump_pcaps = args.dump_pcaps

    if args.payload_len:
        # !!!assuming we only send 3 packets at most for now!!!
        HTTP_REQ_PREFIX = 'GET /' + 'A' * args.payload_len * 3 + '#'

    fo = open("probe_dpi_result", 'w', buffering=0)

    if args.replay:
        cases_to_run = {}
        for line in args.replay:
            line = line.rstrip()
            parts = line.split(',')
            state_id = parts[0]
            packet_idx = int(parts[1])
            tcp_flags = parts[2]
            if tcp_flags == 'None':
                tcp_flags = None
            if state_id not in cases_to_run:
                cases_to_run[state_id] = []
            cases_to_run[state_id].append((packet_idx, tcp_flags))

        i = 0
        for line in args.test_case_file:
            i += 1

            entry = eval(line)
            if entry['state_id'] not in cases_to_run:
                continue

            logger.info("==============================")
            logger.info("== Evaluating test case %i..." % i)
            logger.info("==============================")

            entry['results'] = {}
            for packet_idx, tcp_flags in cases_to_run[entry['state_id']]:
                run_test_case(entry, packet_idx, tcp_flags)

            # results is stored in entry['results']
            fo.write("%s\n" % entry)

    else:
        i = 0
        for line in args.test_case_file:
            i += 1
            if i < START_FROM:
                continue
            if i > END_BY:
                break
            if args.test_case_idx and i < args.test_case_idx:
                continue
            if (i - START_FROM) % args.num_insts != args.split_id:
                continue

            entry = eval(line)

            logger.info("==============================")
            logger.info("== Evaluating test case %i..." % i)
            logger.info("==============================")

            entry['results'] = {}
            run_test_case(entry, args.packet_idx, args.tcp_flags)

            # results is stored in entry['results']
            fo.write("%s\n" % entry)

            if args.test_case_idx:
                break


    fo.close()
    
