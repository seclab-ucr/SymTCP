#!/usr/bin/env python

import re
import sys


test_case_start_pattern = re.compile("\d+ \[State \d+\] TestCaseGenerator:\s*(v0_.* = .*)")
key_value_pattern = re.compile("\s*(v\d_.*?) = \{(.*?)\};.*")


def parse_s2e_result(s2e_log_file):
    concrete_examples = []
    f = open(s2e_log_file, 'r')

    processing_test_case = False
    example = {}

    for line in f:
        if not processing_test_case:
            # check start of test case
            m = test_case_start_pattern.match(line)
            if m:
                processing_test_case = True
                line = m.group(1)
                example = {}
                concrete_examples.append(example)
                m = key_value_pattern.match(line)
                k = m.group(1)
                v = eval('[' + m.group(2) + ']') # convert it to a list of bytes
                example[k] = v
        else:
            # check end of test case
            m = key_value_pattern.match(line)
            if m:
                # processing test case
                k = m.group(1)
                v = eval('[' + m.group(2) + ']') # convert it to a list of bytes
                example[k] = v
            else:
                processing_test_case = False

    f.close()

    return concrete_examples


if __name__ == "__main__":
    if len(sys.argv) == 2:
        log_file_path = sys.argv[1]
    else:
        log_file_path = "/home/alan/Work/extraspace/s2e/projects/tcp/s2e-last/debug.txt"

    concrete_examples = parse_s2e_result(log_file_path)
    for example in concrete_examples:
        print(example)


