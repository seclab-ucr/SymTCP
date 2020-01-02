#!/usr/bin/env python

import re
import sys

DEFAULT_LOG_FILE = "s2e-last/solver-queries.kquery"

p_headline = re.compile("# Query (\d+) -- Type: (.*?), Instructions: (\d+)")

log_file = DEFAULT_LOG_FILE

if len(sys.argv) > 1:
    log_file = sys.argv[1]

print("Log file: %s" % log_file)

f = open(log_file, 'r')

in_query = False
query = None
query_status = None
elapsed = None
solvable = None
is_valid = None
query_id = None
query_type = None
query_inst = None
qvars = []
p = 0

bindings = {}
binding_vars = {}

def process_parenthesis(line, p):
    print("before p: %d" % p)
    print("line: %s" % line)
    for c in line:
        if c == '(':
            p += 1
        elif c == ')':
            p -= 1
    print("after p: %d" % p)
    return p

def find_vars(query):
    qvars = [ term.lstrip('[(').rstrip(')]') for term in query.split() if 'tcp' in term or term[0] == 'N' ]
    qvars = list(set(qvars))
    return qvars

def process_query(query):
    qvars = []
    terms = [ term.lstrip('[').rstrip(']') for term in query.split() ]
    nmap = {}
    p = 0
    for i in range(len(terms)):
        t = terms[i]
        if 'tcp' in t: qvars.append(t)
        if t[0] == 'N' and ':' in t:
            # start of a binding 
            n = t.split(':')[0]
            nmap[n] = (i, p) # push the begining into stack
            print("New binding: %s, %d, %d" % (n, i, p))
        p = process_parenthesis(t, p)
        nmap_new = {}
        for n, tp in nmap.iteritems():
            if tp[1] >= p:
                # done with a binding
                bindings[n] = ' '.join(terms[tp[0]:i+1])
                print(bindings[n])
                print(tp[1], p)
                if tp[1] > p:
                    bindings[n] = bindings[n][:-(tp[1]-p)]
                binding_vars[n] = find_vars(bindings[n])
                print("Done with binding: %s" % bindings[n])
            else: 
                nmap_new[n] = tp
        nmap = nmap_new

    return qvars


qnum = 0

for line in f:
    line = line.rstrip()
    if not line:
        # seperator
        print("QUERY: %s %s %s %s %s" % (query_id, query_type, query_status, (query_type == "InitialValues") and solvable or is_valid, elapsed))
        for vars_ in qvars:
            print("VARS: %s" % list(vars_))
        print("BINDINGS: %s" % bindings)
        qnum += 1
        if qnum > 5: break
        continue

    m = p_headline.match(line)
    if m:
        query_id = m.group(1)
        query_type = m.group(2)
        query_inst = m.group(3)
        query = ""
        query_status = None
        elapsed = None
        solvable = None
        is_valid = None
        qvars = []
        bindings = {}
        continue
    
    if line.startswith("(query "):
        in_query = True
        p = 0
        line = line[7:]
        query += line
        p = process_parenthesis(line, p)
        if p == 0:
            qvars.append(process_query(query))
            query = ""
        continue

    if in_query:
        query += line
        p = process_parenthesis(line, p)
        if p == 0:
            qvars.append(process_query(query))
            query = ""

        if line.endswith("]"):
            in_query = False
        continue

    if line[0] == '#':
        if 'Elapsed' in line:
            parts = line.split()
            query_status = parts[1]
            elapsed = parts[-1]
        elif line.startswith("#   Solvable:"):
            parts = line.split()
            solvable = parts[-1]
        elif line.startswith("#   Is Valid:"):
            parts = line.split()
            is_valid = parts[-1]
        continue

f.close()

