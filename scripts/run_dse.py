#!/usr/bin/env python
# We are using BFS to find the shortest path that can reach the target

import logging
import os
import subprocess
import sys
import time

from parse_s2e_result import parse_s2e_result
from triage import triage
from dep_analysis import dep_analysis


minimum_solution = True

logFormatter = logging.Formatter("%(asctime)-15s [%(levelname)s] %(message)s")
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

fileHandler = logging.FileHandler("run_dse.log", mode='w')
fileHandler.setFormatter(logFormatter)
logger.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
logger.addHandler(consoleHandler)

S2E_DIR = "/home/alan/Work/extraspace/s2e"
CC_BL_DIR = "./static"
GEN_CC_BL_SCRIPT = S2E_DIR + "/kernel/findCallChainsAndBlacklists.py"
GEN_DIRECTOR_SCRIPT  = "./gen_director.py"
PROBING_SCRIPT = "./probe_s2e.py"
PROC_RESULT_SCRIPT = "./proc_result.py"

KERNEL_CU_OFFSET = 0xb9757390

S2E_TIMEOUT = 3600

# initial target address is ultimately where we stop
initial_target_addr = None


class Prepacket(object):

    def __init__(self, packet, director):
        self.packet = packet
        self.director = director

def load_status():
    try:
        f = open('status', 'r')
        status = eval(f.read())
        f.close()
    except IOError:
        status = {}
    return status

def save_status():
    f = open('status', 'w')
    f.write("%s" % status)
    f.close()

def load_deps():
    try:
        f = open('deps', 'r')
        dependencies = eval(f.read())
        f.close()
    except IOError:
        dependencies = {}
    return dependencies

def save_deps():
    f = open('deps', 'w')
    f.write("%s" % dependencies)
    f.close()

def load_result(folder):
    result = {}
    try:
        f = open(folder + '/packets')
        result['packets'] = eval(f.read())
        f.close()
    except IOError:
        result['packets'] = []

    try:
        f = open(folder + '/prepackets')
        result['prepackets'] = eval(f.read())
        f.close()
    except IOError:
        result['prepackets'] = []

    try:
        f = open(folder + '/branches')
        result['branches'] = eval(f.read())
        f.close()
    except IOError:
        result['branches'] = []

    results[folder] = result
    return result

def exit():
    save_status()
    save_deps()
    sys.exit(0)


# 'status' structure stores necessary information to perform
# directed symbolic execution for each target address, such as
# call chains and blacklists, also, including packet sequences
# that can reach this target address.
# Example:
# status = {
#   0xabcd1234: {
#     'callchains_file': 'cc_abcd1234',
#     'blacklists_file': 'bl_abcd1234',
#     'result_dirs: {
#       0: 's2e-out-6',
#       1: 's2e-out-7',
#       2: 's2e-out-10',
#     },
#     'packet_sequences': [
#       [{pkt1}, {pkt2}, ...],
#       ...
#     ]
#   }
#   ...
# }
status = load_status()

# 'results' structure stores the results generated from each 's2e-out' dir,
# which should have a 1-to-1 mapping with the call chains, i.e. each call chain
# have only one result dir.
# Example:
# results = {
#   's2e-out-0': {
#     'prepackets': [{'v4_tcp_win_4': [0, 0], 'v1_tcp_ack_num_1': [0, 0, 0, 0], 'v2_tcp_doff_reserved_flags_2': [80], 'v5_tcp_csum_5': [0, 0], 'v6_tcp_urg_ptr_6': [0, 0], 'v0_tcp_seq_num_0': [0, 0, 0, 0], 'v3_tcp_flags_3': [2]}, {'v4_tcp_win_4': [0, 0], 'v1_tcp_ack_num_1': [187, 40, 75, 16], 'v2_tcp_doff_reserved_flags_2': [80], 'v5_tcp_csum_5': [0, 0], 'v6_tcp_urg_ptr_6': [0, 0], 'v0_tcp_seq_num_0': [0, 0, 114, 17], 'v3_tcp_flags_3': [16]}],
#     'packets': [{'v4_tcp_win_4': [0, 0], 'v1_tcp_ack_num_1': [0, 0, 0, 0], 'v2_tcp_doff_reserved_flags_2': [80], 'v5_tcp_csum_5': [0, 0], 'v6_tcp_urg_ptr_6': [0, 0], 'v0_tcp_seq_num_0': [0, 0, 0, 0], 'v3    _tcp_flags_3': [2]}]
#     'branches': {'yes': [('0xc1783ee3', 1), ('0xc1783ec3', 1), ('0xc1783ed6', 1), ('0xc1783bf9', 1), ('0xc1783c33', 1), ('0xc1783bb9', 1), ('0xc1783c0f', 1), ('0xc1783fc7', 1), ('0xc1783be4', 1), ('0xc1783cf7', 1), ('0xc1783ef7', 1)], 'never': [('0xc1783452', 1)], 'no': [('0xc1783bf9', 1), ('0xc1783c0f', 1), ('0xc1783452', 1)]}
#   }
#   ...
# }
results = {}

# 'deps' structure stores the dependence relationship between addresses
# Example:
# deps = {
#   0xabcd1234: [0x11111111, 0x22222222],
#   ...
# }
dependencies = load_deps()


def gen_prepackets(target_addr, packetchain, all_prepackets):
    pass

def gen_call_chains_and_black_lists(target_addr, cc_file, bl_file):
    # we are using CFG of ipv4 built-in.o, so we need to convert kernel address to cu address
    # we'll convert it back in gen_director.py
    target_addr -= KERNEL_CU_OFFSET
    cmd = "%s %s %s 0x%x" % (GEN_CC_BL_SCRIPT, cc_file, bl_file, target_addr)
    os.system(cmd)

def initialize(target_addr):
    status[target_addr] = {}
    cc_file = "%s/cc_%x" % (CC_BL_DIR, target_addr)
    bl_file = "%s/bl_%x" % (CC_BL_DIR, target_addr)
    status[target_addr]['callchains_file'] = cc_file
    status[target_addr]['blacklists_file'] = bl_file
    status[target_addr]['result_dirs'] = {} # indexed by call chain index 
    status[target_addr]['packet_sequences'] = []

def update_conf_packet_counter(counter):
    cmd = "sed -i -r 's/concretePacketCounter = [0-9]+,/concretePacketCounter = %d,/' s2e-config.lua" % counter
    os.system(cmd)

def launch_s2e():
    logger.debug("Launching S2E...")
    p = subprocess.Popen("./launch-s2e.sh", shell=True)
    p2 = subprocess.Popen("sudo %s" % PROBING_SCRIPT, shell=True)
    start_time = time.time()
    while p.poll() is None:
        if time.time() - start_time >= S2E_TIMEOUT:
            logger.warning("S2E timeout. terminating.")
            p.kill()
            break
        time.sleep(1)
    p2.kill()
    
def propagate_reachability(reached_addr):
    for addr, deps in dependencies.iteritems():
        if reached_addr in deps:
            # try if we can reach addr
            for prepackets in status[reached_addr]['packet_sequences']:
                reached = run_single_step_dse(addr, prepackets)

def run_single_step_dse(target_addr, prepackets=[]):
    if target_addr not in status:
        initialize(target_addr)

    logger.info("Running directed symbolic execution towards address 0x%x..." % target_addr)

    # find prepackets
    #logger.debug("Finding prepackets...")
    #prepackets = []
    #gen_prepackets(target_addr, prepackets)

    cc_file = status[target_addr]['callchains_file']
    bl_file = status[target_addr]['blacklists_file']
    gen_call_chains_and_black_lists(target_addr, cc_file, bl_file)
    f = open(cc_file, 'r')
    callchains = [ callchain for callchain in f.read().split('\n') if callchain.strip() ]
    f.close()
    num_callchains = len(callchains)

    reached = False

    for idx in xrange(num_callchains):
        logger.debug("Using call chain %d." % idx)
        director_file = "director1.txt"
        cmd = "%s %s %s %d > %s" % (GEN_DIRECTOR_SCRIPT, cc_file, bl_file, idx, director_file)
        os.system(cmd)

        os.system("rm -rf directors && mkdir directors")
        os.system("mv %s directors/" % director_file)

        # launch s2e
        update_conf_packet_counter(0)
        launch_s2e()

        result_dir = os.path.basename(os.path.realpath('s2e-last'))
        status[target_addr]['result_dirs'][idx] = result_dir

        # process result
        # we call an external script to process the result, so we can also separate the result processing task
        os.system("%s %s" % (PROC_RESULT_SCRIPT, result_dir))
        result = load_result(result_dir)
        if result['packets']:
            # reached
            logger.info("Reached the target at 0x%x!" % target_addr)
            for packet in result['packets']:
                status[target_addr]['packet_sequences'].append([prepackets + packet])

            if target_addr == initial_target_addr:
                logger.info("Found a solution!")
                exit()
            else:
                # suspend the current backwards process and do a forward propagation to see if we can reach the initial target
                propagate_reachability(target_addr)

            reached = True

        # dependence analysis
        for never_branch, cnt in result['branches']['never']:
            deps = dep_analysis(never_branch)
            if not deps:
                logger.warning("Dependence analysis failed.")

            dependencies[never_branch] = deps

        save_deps()
        save_status()

    return reached


def run_multi_step_dse(target_addr):
    if target_addr not in status:
        initialize(target_addr)

    if status[target_addr]['packet_sequences']:
        # already reached
        logger.debug("%d packet sequences can reach the target." % len(status[target_addr]['packet_sequences']))
        return status[target_addr]['packet_sequences']

    target_addrs = [ target_addr ]

    # backwards dep bruteforce
    while target_addrs:
        tgt_addr = target_addrs[0]
        target_addrs = target_addrs[1:]
    
        reached = run_single_step_dse(tgt_addr)

        # recursively try all the dependencies
        for result_dir in status[tgt_addr]['result_dirs'].values():
            for never_branch, _ in results[result_dir]['branches']['never']:
                for dep in dependencies[never_branch]:
                    target_addrs.append(dep)


if __name__ == "__main__":
    initial_target_addr = int(sys.argv[1], 16)

    if initial_target_addr < 0xc1000000:
        initial_target_addr += KERNEL_CU_OFFSET
    run_multi_step_dse(initial_target_addr)


