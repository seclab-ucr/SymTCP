#!/usr/bin/env python

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

from scapy.all import sr1, TCP, IP, Raw, hexdump, sr, send, conf, L3RawSocket

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

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

consoleHandler = logging.StreamHandler()
logger.addHandler(consoleHandler)


# time wait for server's reply
# for localhost use a small value such as 0.5s
# for remote host use a larger value such as 3s
TIME_WAIT_SERVER_ACK = 3
# wait additional 0.5s between packets
INTERVAL_BETWEEN_PACKET = 0.5

PROJECT_DIR = "/home/alan/Work/s2e/s2e/projects/tcp"
LOG_FILE_PATH = "/home/alan/Work/s2e/s2e/projects/tcp/s2e-last/0/debug.txt"

SYN = 0x02
RST = 0x04
ACK = 0x10

SERVER_IP = '172.20.0.2'
SERVER_PORT = 5555

conf.L3socket=L3RawSocket

# bad keyword
HTTP_REQ = 'GET /search.php?keyword=ultrasurf HTTP/1.1\r\nHost: search.kankan.com\r\n\r\n'

# error code
ERR_NO_SYNACK = 1
ERR_UNSOLVABLE = 2


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


def run_s2e(cnum, snum):
    os.system("sed -i 's/concretePacketCounter = [0-9]\+/concretePacketCounter = %d/' s2e-config.lua" % cnum)
    os.system("sed -i 's/symbolicPacketCounter = [0-9]\+/symbolicPacketCounter = %d/' s2e-config.lua" % snum)

    # starting s2e with user alan, because we are now running as root
    pw_record = pwd.getpwnam('alan')
    user_name      = pw_record.pw_name
    user_home_dir  = pw_record.pw_dir
    user_uid       = pw_record.pw_uid
    user_gid       = pw_record.pw_gid
    cwd = os.getcwd()
    env = os.environ.copy()
    env[ 'HOME'     ]  = user_home_dir
    env[ 'LOGNAME'  ]  = user_name
    env[ 'PWD'      ]  = cwd
    env[ 'USER'     ]  = user_name
    p = subprocess.Popen("./launch-s2e.sh", shell=True, preexec_fn=demote(user_uid, user_gid), cwd=cwd, env=env)
    return p

"""
def is_running(pid):
    try:
        os.kill(pid, 0)
    except OSError as err:
        if err.errno == errno.ESRCH:
            return False
    return True

def get_qemu_pid():
    pid_file = os.path.join(PROJECT_DIR, "qemu.pid")
    if not os.path.exists(pid_file):
        return -1

    f = open(pid_file, 'r')
    pid = int(f.read())
    f.close()

    if not is_running(pid):
        return -1

    return pid

def wait_for_s2e():
    pid = get_qemu_pid()
    if pid != -1:
        while is_running(pid):
            sleep(1)
""" 

client_port = random.randint(10000, 40000)

def get_next_client_port():
    global client_port
    client_port += 1
    if client_port > 60000:
        client_port = 10000
    return client_port

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

def solve_constraints(constraints, args={}):
    logger.info("Solving constraints...")
    logger.debug("args: %s" % args)
    s = Solver()
    constraints = constraints.split('\n')
    constraints_new = []
    client_isn_var = ''
    server_isn_var = ''
    ins_pkt_seq_var_orig = ''
    ins_pkt_ack_var_orig = ''
    ins_pkt_flags_var_orig = ''
    ins_pkt_seq_var = ''
    ins_pkt_ack_var = ''
    ins_pkt_flags_var = ''
    # check if need to constrain TCP flags and SEQ and ACK for insertion packet
    for k in args:
        if 'tcp_seq_num' in k:
            ins_pkt_seq_var_orig = k
        if 'tcp_ack_num' in k:
            ins_pkt_ack_var_orig = k
        if 'tcp_flags' in k:
            ins_pkt_flags_var_orig = k

    need_to_declare_client_isn_var = True
    need_to_declare_server_isn_var = True
    need_to_declare_ins_pkt_seq_var = True
    need_to_declare_ins_pkt_ack_var = True
    need_to_declare_ins_pkt_flags_var = True

    for line in constraints:
        if line and line != '(check-sat)' and line != '(exit)':
            constraints_new.append(line)
        if line.startswith("(declare-") and "tcp_seq_num1_" in line:
            client_isn_var = line.split()[1]
            need_to_declare_client_isn_var = False
        if line.startswith("(declare-") and "tcp_svr_isn_" in line:
            server_isn_var = line.split()[1]
            need_to_declare_server_isn_var = False
        if line.startswith("(declare-") and ins_pkt_seq_var_orig and ins_pkt_seq_var_orig + '_' in line:
            ins_pkt_seq_var = line.split()[1]
            need_to_declare_ins_pkt_seq_var = False
        if line.startswith("(declare-") and ins_pkt_ack_var_orig and ins_pkt_ack_var_orig + '_' in line:
            ins_pkt_ack_var = line.split()[1]
            need_to_declare_ins_pkt_ack_var = False
        if line.startswith("(declare-") and ins_pkt_flags_var_orig and ins_pkt_flags_var_orig + '_' in line:
            ins_pkt_flags_var = line.split()[1]
            need_to_declare_ins_pkt_flags_var = False

    if 'client_isn' in args and need_to_declare_client_isn_var:
        logger.debug("Declaring the client ISN variable...")
        constraints_new.append('(declare-fun tcp_seq_num1 () (Array (_ BitVec 32) (_ BitVec 8) ) )')
    if 'server_isn' in args and need_to_declare_server_isn_var:
        logger.debug("Declaring the server ISN variable...")
        constraints_new.append('(declare-fun tcp_svr_isn () (Array (_ BitVec 32) (_ BitVec 8) ) )')
    if ins_pkt_seq_var_orig and need_to_declare_ins_pkt_seq_var:
        logger.debug("Declaring a new tcp seq num variable...")
        constraints_new.append('(declare-fun %s () (Array (_ BitVec 32) (_ BitVec 8) ) )' % ins_pkt_seq_var_orig)
        ins_pkt_seq_var = ins_pkt_seq_var_orig
    if ins_pkt_ack_var_orig and need_to_declare_ins_pkt_ack_var:
        logger.debug("Declaring a new tcp ack num variable...")
        constraints_new.append('(declare-fun %s () (Array (_ BitVec 32) (_ BitVec 8) ) )' % ins_pkt_ack_var_orig)
        ins_pkt_ack_var = ins_pkt_ack_var_orig
    if ins_pkt_flags_var_orig and need_to_declare_ins_pkt_flags_var:
        logger.debug("Declaring a new tcp flags variable...")
        constraints_new.append('(declare-fun %s () (Array (_ BitVec 32) (_ BitVec 8) ) )' % ins_pkt_flags_var_orig)
        ins_pkt_flags_var = ins_pkt_flags_var_orig

    if 'client_isn' in args and client_isn_var:
        client_isn = args['client_isn']
        v = []
        for i in range(4):
            v.append(client_isn % 256)
            client_isn /= 256
        v.reverse()
        # client ISN is network-order because we symbolized a packet field
        new_constraint = "(assert (and (= (select %s (_ bv0 32) ) #x%02x) (= (select %s (_ bv1 32) ) #x%02x) (= (select %s (_ bv2 32) ) #x%02x) (= (select %s (_ bv3 32) ) #x%02x) ) )" % (client_isn_var, v[0], client_isn_var, v[1], client_isn_var, v[2], client_isn_var, v[3])
        logger.debug("Client ISN constraint: " + new_constraint)
        constraints_new.append(new_constraint)
    if 'server_isn' in args and server_isn_var:
        server_isn = args['server_isn']
        v = []
        for i in range(4):
            v.append(server_isn % 256)
            server_isn /= 256
        # server ISN is host order because we symbolized a local variable
        new_constraint = "(assert (and (= (select %s (_ bv0 32) ) #x%02x) (= (select %s (_ bv1 32) ) #x%02x) (= (select %s (_ bv2 32) ) #x%02x) (= (select %s (_ bv3 32) ) #x%02x) ) )" % (server_isn_var, v[0], server_isn_var, v[1], server_isn_var, v[2], server_isn_var, v[3])
        logger.debug("Server ISN constraint: " + new_constraint)
        constraints_new.append(new_constraint)
    if ins_pkt_seq_var_orig:
        # need to constrain TCP seq num
        seq_num = args[ins_pkt_seq_var_orig]
        v = []
        for i in range(4):
            v.append(seq_num % 256)
            seq_num /= 256
        v.reverse()
        # TCP SEQ number is network-order because we symbolized a packet field
        new_constraint = "(assert (and (= (select %s (_ bv0 32) ) #x%02x) (= (select %s (_ bv1 32) ) #x%02x) (= (select %s (_ bv2 32) ) #x%02x) (= (select %s (_ bv3 32) ) #x%02x) ) )" % (ins_pkt_seq_var, v[0], ins_pkt_seq_var, v[1], ins_pkt_seq_var, v[2], ins_pkt_seq_var, v[3])
        logger.debug("Insertion packet SEQ number constraint: " + new_constraint)
        constraints_new.append(new_constraint)
    if ins_pkt_ack_var_orig:
        # need to constrain TCP ack num
        ack_num = args[ins_pkt_ack_var_orig]
        v = []
        for i in range(4):
            v.append(ack_num % 256)
            ack_num /= 256
        v.reverse()
        # TCP ACK number is network-order because we symbolized a packet field
        new_constraint = "(assert (and (= (select %s (_ bv0 32) ) #x%02x) (= (select %s (_ bv1 32) ) #x%02x) (= (select %s (_ bv2 32) ) #x%02x) (= (select %s (_ bv3 32) ) #x%02x) ) )" % (ins_pkt_ack_var, v[0], ins_pkt_ack_var, v[1], ins_pkt_ack_var, v[2], ins_pkt_ack_var, v[3])
        logger.debug("Insertion packet ACK number constraint: " + new_constraint)
        constraints_new.append(new_constraint)
    if ins_pkt_flags_var_orig:
        # need to constrain TCP flags
        tcp_flags = args[ins_pkt_flags_var_orig]
        #tcp_flags_constraint = "(assert (= false (= (_ bv0 64) (bvand ((_ zero_extend 56) (select %s (_ bv0 32))) (_ bv%d 64)))))" % (tcp_flags_var, tcp_flags)
        #tcp_flags_constraint = "(assert (= (select %s (_ bv0 32 ) ) #x%02x) )" % (tcp_flags_var, tcp_flags)
        new_constraint = "(assert (= (_ bv%d 64) (bvand ((_ zero_extend 56) (select %s (_ bv0 32))) (_ bv23 64))))" % (tcp_flags, ins_pkt_flags_var)
        logger.debug("Insertion packet TCP flags constraint: " + new_constraint)
        constraints_new.append(new_constraint)

    constraints = '\n'.join(constraints_new)

    F = parse_smt2_string(constraints)
    #logger.debug(F.sexpr())
    s.add(F)
    res = s.check()
    #logger.debug(res)
    if res == sat:
        example = {}
        m = s.model()
        #logger.debug(m)
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
            elif 'tcp_options' in k:
                example[k] = get_value_from_model(m, d, 40)

        logger.info("---------Solved Example---------")
        logger.info(example)
        logger.info("---------Example End---------")
        return example
    else:
        logger.debug("####### Cannot solve constraint! #######")

    return None

# update the packet with concrete example of packet with index `idx`
def update_pkt_with_example(pkt, example, idx):
    logger.info("==========")
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
    logger.info("==========")

    #ls(pkt)
    #pkt.show()
    #pkt.show2()
    #wireshark(pkt)
    #hexdump(pkt)
    #send(pkt)


def send_probing_packets(test_case, payload_len, packet_num):
    #logger.debug(test_case)

    if 'c' in test_case['state_id']:
        bad_checksum_case = True
    else:
        bad_checksum_case = False

    client_port = get_next_client_port()

    # client initial sequence number
    client_isn = random.getrandbits(32)
    # server initial sequence number
    server_isn = 0

    args = {}
    #args['client_isn'] = client_isn

    # initialize SEQ and ACK
    client_seq = client_isn
    client_ack = 0
    server_seq_recved = False
    server_ack_recved = False
    server_seq = 0
    server_ack = 0

    example = solve_constraints(test_case['constraints'], args)
    if not example:
        logger.warn("Failed to solve constraints.")
        return -ERR_UNSOLVABLE

    for k, v in example.iteritems():
        if 'tcp_seq_num1' in k:
            client_seq = (v[0] << 24) + (v[1] << 16) + (v[2] << 8) + v[3]
    # if constraint solver has generated a client ISN, then use it, otherwise use our own
    if client_seq != client_isn:
        # constraint solve has generated a new client ISN
        client_isn = client_seq
    # constrain the client ISN for later pacekts to eliminate randomness
    args['client_isn'] = client_isn

    # send pre-packets
    for i in range(1, packet_num + 1):
        logger.info("---------Packet #%d---------" % i)

        data_offset = 0
        # get the client seq number and data offset from the example if there's any
        client_seq_var_name = 'tcp_seq_num' + str(i)
        data_off_var_name = 'tcp_doff_reserved_flags' + str(i)
        for k, v in example.iteritems():
            if client_seq_var_name in k:
                client_seq = (v[0] << 24) + (v[1] << 16) + (v[2] << 8) + v[3]
            if data_off_var_name in k:
                data_offset = (v[0] >> 4) * 4

        payload = ''
        if payload_len:
            if i == 1:
                payload = '\xff' * (data_offset - 20) + HTTP_REQ
            else:
                # calculate the payload using client seq number
                if client_seq < client_isn - 2**31:
                    offset = client_seq + 2**32 - client_isn - 1
                else:
                    offset = client_seq - client_isn - 1
                if offset < 0: 
                    offset = 0
                payload = '\xff' * (data_offset - 20) + HTTP_REQ[offset:] 
            payload = payload[:payload_len]
            if len(payload) < payload_len:
                payload += 'A' * (payload_len - len(payload))

        if i == packet_num and bad_checksum_case:
            pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, flags='S', seq=client_seq, chksum=0xffff)/Raw(load=payload)
        else:
            pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, flags='S', seq=client_seq)/Raw(load=payload)

        update_pkt_with_example(pkt, example, i)
        #if i == packet_num:
        #    pkt[TCP].seq = server_ack
        logger.info("payload: %s" % ' '.join([ "%02x" % ord(c) for c in pkt[TCP].payload.load]))
        pkt[IP].ttl = 163 # to bypass the iptables rule

        #hexdump(pkt)
        logger.info("Sending packet...")
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
                    args['server_isn'] = server_isn
                    server_seq = server_isn + 1

                    example = solve_constraints(test_case['constraints'], args)
                    if not example:
                        logger.warn("Failed to solve constraints.")
                        return -ERR_UNSOLVABLE
            else:
                logger.warn("Received non TCP packet.")

        if i == 1 and packet_num > 1 and 'server_isn' not in args:
            logger.warn("Didn't receive SYN/ACK packet after sending the first packet.")
            return -ERR_NO_SYNACK

        #sleep(INTERVAL_BETWEEN_PACKET)

    return 0

def probe_s2e(test_case, payload_len=0):
    disable_other_packets()

    #sys.stdout.write("Waiting for S2E to start...")
    #sys.stdout.flush()
    #while get_qemu_pid() == -1:
    #    sys.stdout.write('.')
    #    sys.stdout.flush()
    #    time.sleep(1)
    #print("")

    packet_num = get_packet_num(test_case['example'])

    p_s2e = run_s2e(packet_num, 0)

    print("Waiting 15s for S2E to fully start...")
    time.sleep(15)

    fh = logging.FileHandler("./s2e-last/prober.log")
    logger.addHandler(fh)

    ret = send_probing_packets(test_case, payload_len, packet_num)

    if ret != 0:
        os.system("killall -9 qemu-system-x86_64")
        sleep(1)
    else:
        # wait for s2e to finish
        print("Waiting for s2e to finish...")
        #wait_for_s2e()
        p_s2e.wait()

    fh.close()
    logger.removeHandler(fh)

    enable_other_packets()

    #raw_input("Press ENTER to continue...")
    return ret

def verify_result(dp):
    bad_checksum_edges = (
        '0xffffffff817900be->0xffffffff817900c4', 
        '0xffffffff8178f011->0xffffffff8178f013',
        '0xffffffff81784cfa->0xffffffff81784a30',
        '0xffffffff81784a2a->0xffffffff81784a30',
    )
    logger.info("Should reach drop point: %s" % dp)
    output = ''
    try:
        output = subprocess.check_output("grep '\] Terminating state early: Reached ' " + LOG_FILE_PATH, shell=True)
    except:
        pass
    if output:
        #print(output)
        lines = output.rstrip().split('\n')
        if len(lines) == 1:
            parts = lines[0].split()
            logger.info("Reached drop point: %s" % parts[-1])
            if dp in bad_checksum_edges and parts[-1] in bad_checksum_edges:
                # both are bad checksum cases
                # since bad checksum cases are not terminated during symbolic execution, mismatch could happen
                logger.info("Mismatched bad checksum cases. Succeeded.")
                return True
            if parts[-1] == dp:
                logger.info("Succeeded.")
                return True
        elif len(lines) > 1:
            for line in lines:
                parts = lines[0].split()
                logger.info("Reached drop point: %s" % parts[-1])
    else:
        logger.info("Not reaching any drop point.")
    logger.info("Failed.")
    return False


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Probe S2E with test cases generated from symbolic execution.')
    parser.add_argument('test_case_file', type=argparse.FileType('r'), help='test case file')
    parser.add_argument('-t', dest='test_case_idx', type=int, help='test case index')
    parser.add_argument('--start-from', dest='start_from', type=int, help='test case start index')
    parser.add_argument('--end-by', dest='end_by', type=int, help='test case end index')
    parser.add_argument('-p', dest='payload_len', type=int, default=0, help='TCP payload length (because header len is symbolic, payload may be counted as optional header')
    parser.add_argument('-D', '--debug', action='store_true', help='turn on debug mode')
    args = parser.parse_args()

    fo = open("probe_s2e_result", 'w', buffering=0)
    i = 0
    for line in args.test_case_file:
        i += 1
        if args.test_case_idx and i < args.test_case_idx or args.start_from and i < args.start_from:
            continue
        entry = eval(line)
        logger.info("==============================")
        logger.info("== Evaluating test case %i..." % i)
        logger.info("==============================")
        ret = probe_s2e(entry, args.payload_len)

        retry = 0
        while ret == -ERR_NO_SYNACK or ret == -ERR_UNSOLVABLE:
            retry += 1
            ret = probe_s2e(entry, args.payload_len)
            if retry > 3:
                break

        entry['valid'] = verify_result(entry['drop_points'][0])
        entry['output_dir'] = os.path.basename(os.path.realpath('s2e-last'))
        fo.write("%s\n" % entry)
        if args.test_case_idx or args.end_by and i >= args.end_by:
            break
        if args.debug:
            if not entry['valid'] and ret != -ERR_UNSOLVABLE:
                raw_input("Press ENTER to continue...")
    fo.close()
    
