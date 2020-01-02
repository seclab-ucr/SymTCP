#!/usr/bin/env python

import re
import sys

from z3 import *

from s2e_utils import *

set_param('model_compress', False)


p_var_name = re.compile('a!\d+')


args = None

stats = {'equal': 0, 'larger': 0, 'smaller': 0, 'plusone': 0}


MOD32 = 2**32

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

def find_related_vars(constraints, var_name):
    all_vars = {}
    lines = constraints.split('\n')
    elements = []
    level = 0
    target_level = 3
    s = ''
    for c in constraints:
        s += c
        if 'let' in s:
            target_level += 1
            s = ''
        if c == '(':
            level += 1
            if level == target_level:
                s = ''
        elif c == ')':
            level -= 1
            if level == target_level:
                elements.append(s.strip())
                s = ''

    for e in elements:
        v = e.split(' ', 1)[0]
        if p_var_name.match(v):
            all_vars[v] = e

    related_vars = [{}]
    # find direct vars
    for v, e in all_vars.iteritems():
        if e.find(var_name) > 0:
            related_vars[0][v] = e

    def has_v(v):
        for vd in related_vars:
            if v in vd:
                return True
        return False

    # find indirect vars
    changed = True if related_vars else False
    while changed:
        changed = False
        new_related_vars = {}
        for v, e in all_vars.iteritems():
            if has_v(v):
                # already in related_vars
                continue
            for v2 in related_vars[-1]:
                idx = e.find(v2)
                if idx > 0 and not e[idx + len(v2)].isdigit():
                    new_related_vars[v] = e

        if new_related_vars:
            changed = True
            related_vars.append(new_related_vars)

    return related_vars

def find_related_constraints(constraints, var_name):
    print(constraints)
    related_vars = find_related_vars(constraints, var_name)
    print('-------------------------------------')
    for i in range(len(related_vars)):
        vd = related_vars[i]
        for v, e in vd.iteritems():
            print('\t' * i + e)
            print('-------------------------------------')

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
        elif 'tcp_svr_isn' in k:
            field_val = get_value_from_model(m, d, 4)
            example[k] = field_val
    return example

def solve_constraints(constraints, params={}):
    s = Solver()
    bnums = re.findall('\?B(\d+)', constraints)
    try:
        bmax = max([int(num) for num in bnums])
    except:
        print("Failed to find bmax.")
        print(constraints)
    constraints = constraints.split('\n')
    constraints_new = []
    varnames = {}
    #constraints_new.append("(set-option :smt.arith.random_initial_value true)")
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

    #if 'seq2_gt_seq1' in params:
    #    if 'tcp_seq_num1' not in varnames:
    #        constraints_new.append("(declare-fun tcp_seq_num1 () (Array (_ BitVec 32) (_ BitVec 8) ) )")
    #        varnames['tcp_seq_num1'] = 'tcp_seq_num1'
    #    if 'tcp_seq_num2' not in varnames:
    #        constraints_new.append("(declare-fun tcp_seq_num2 () (Array (_ BitVec 32) (_ BitVec 8) ) )")
    #        varnames['tcp_seq_num2'] = 'tcp_seq_num2'
    #    constraints_new.append("(assert (let ( (?B{0:d} ((_ zero_extend 32)  ((_ extract 31  0)  (bvlshr ((_ zero_extend 32)  ((_ extract 31  0)  (bvsub  ((_ zero_extend 32) (concat  (select {1} (_ bv0 32) ) (concat  (select {1} (_ bv1 32) ) (concat  (select {1} (_ bv2 32) ) (select {1} (_ bv3 32) ) ) ) ) ) ((_ zero_extend 32) (concat  (select  {2} (_ bv0 32) ) (concat  (select {2} (_ bv1 32) ) (concat  (select {2} (_ bv2 32) ) (select {2} (_ bv3 32) ) ) ) ) ) ) ) ) (_ bv31 64) ) ) ) ) ) (=  false (=  (_ bv0 64) (bvand  (bvand  ?B{0:d} ?B{0:d} ) (_ bv255 64) ) ) ) ) )".format(bmax, varnames['tcp_seq_num1'], varnames['tcp_seq_num2']))
    #constraints_new.append("(check-sat-using (using-params qflra :random_seed 3))")

    constraints = '\n'.join(constraints_new)

    #print(constraints)

    F = parse_smt2_string(constraints)
    if not args.check_mode and args.print_constraints:
        print(F.sexpr())
    s.add(F)
    res = s.check()
    if not args.check_mode:
        print(res)
    if res == sat:
        m = s.model()
        if not args.check_mode:
            #print(m)
            example = extract_example_from_model(m)
            print(example)
            """
            seq_num1_var = seq_num2_var = None
            for k, v in example.iteritems():
                if 'tcp_seq_num1' in k:
                    seq_num1_var = k
                elif 'tcp_seq_num2' in k:
                    seq_num2_var = k
            if seq_num1_var and seq_num2_var:
                seq_num1 = 0
                for i in range(4):
                    seq_num1 *= 256
                    seq_num1 += example[seq_num1_var][i]
                seq_num2 = 0
                for i in range(4):
                    seq_num2 *= 256
                    seq_num2 += example[seq_num2_var][i]
                print("seq num 1: 0x%08x, seq num 2: 0x%08x" % (seq_num1, seq_num2))
                if seq_num1 == seq_num2:
                    stats['equal'] += 1
                elif before(seq_num1, seq_num2):
                    stats['larger'] += 1
                    if seq_num2 == add(seq_num1, 1):
                        stats['plusone'] += 1
                else:
                    stats['smaller'] += 1
            """

        return True
    else:
        # find related constraints
        #find_related_constraints(str(F.sexpr()), 'svr_isn')
        #find_related_constraints(str(F.sexpr()), 'v9_tcp_ack_num2_9')
        #find_related_constraints(str(F.sexpr()), 'v16_tcp_ack_num3_111')
        return False

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Solve a specific constraint in the test cases generated from symbolic execution.')
    parser.add_argument('test_case_file', type=argparse.FileType('r'), help='test case file')
    parser.add_argument('-t', dest='test_case_idx', type=int, help='test case index')
    parser.add_argument('-i', dest='pkt_idx', type=int, help='packet index in the test case')
    parser.add_argument('-p', dest='payload_len', type=int, default=20, help='TCP options and payload len.')
    parser.add_argument('--check', dest='check_mode', default=False, action='store_true', help='just check if all test cases are satisfiable')
    parser.add_argument('--pp', dest='print_packets', default=False, action='store_true', help='Print out the concete packets.')
    parser.add_argument('--pc', dest='print_constraints', default=False, action='store_true', help='Print out the constraints and solver result.')
    args = parser.parse_args()

    import random
    params = {
#        'seq2_gt_seq1': True,
        #'tcp_flags1': 194, 
        #'tcp_doff_reserved_flags1': 128, 
        #'tcp_options1': 45906083991175287736851285564319850120479768576L, 
        #'tcp_seq_num1': 185342208,
        #'tcp_svr_isn': 0x77777777,
    }

    if args.check_mode:
        i = 0
        fo = open(args.test_case_file.name + '.filtered', 'w')
        for line in args.test_case_file:
            i += 1
            entry = eval(line)
            print("--------------Checking constraint for test case %d-----------------" % i)
            if not solve_constraints(entry['constraints'], params):
                print("Found BUG! in state %s" % entry['state_id'])
                #break
            else:
                fo.write(line)
        fo.close()

    else:
        i = 0
        for line in args.test_case_file:
            i += 1
            if i < args.test_case_idx:
                continue
            entry = eval(line)
            print("--------------Checking constraint for test case %d-----------------" % i)
            #for j in range(100):
            solve_constraints(entry['constraints'], params)
            if args.test_case_idx:
                break

    #print(stats)

