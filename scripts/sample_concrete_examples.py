#!/usr/bin/env python


import os
import sys
import random


# number of test cases after sampling
TARGET_NUM = 10000
# threshold, if <= threshold, do not sample
THRESHOLD = 648


dp_stats = {}
total_count = 0

f = open(sys.argv[1], 'r')

for line in f:
    entry = eval(line)
    if str(entry['drop_points']) not in dp_stats:
        dp_stats[str(entry['drop_points'])] = 0
    dp_stats[str(entry['drop_points'])] += 1
    total_count += 1

f.close()

print("-----------------------------")
print("Total number: %d" % total_count)
print("Threshold: %d" % THRESHOLD)
print("Target number: %d" % TARGET_NUM)
print("-----------------------------")

print("Before sampling:")
sorted_dp_stats = sorted(dp_stats.items(), key=lambda kv: kv[1])
for k, v in sorted_dp_stats:
    print("%d\t%s" % (v, k))
print("")


no_sample_count = 0
need_to_sample = {}

for dp in dp_stats:
    if dp_stats[dp] > THRESHOLD:
        need_to_sample[dp] = True
    else:
        no_sample_count += dp_stats[dp]

before_sample_count = total_count - no_sample_count
after_sample_count = TARGET_NUM - no_sample_count

dp_stats2 = {}

f = open(sys.argv[1], 'r')
fo = open(sys.argv[1] + '.sample', 'w')

total_count = 0
for line in f:
    entry = eval(line)
    if str(entry['drop_points']) not in dp_stats2:
        dp_stats2[str(entry['drop_points'])] = 0
    if str(entry['drop_points']) in need_to_sample:
        x = random.randint(1, before_sample_count)
        if x <= after_sample_count:
            fo.write(line)
            dp_stats2[str(entry['drop_points'])] += 1
            total_count += 1
    else:
        fo.write(line)
        dp_stats2[str(entry['drop_points'])] += 1
        total_count += 1

f.close()
fo.close()


print("After sampling:")
sorted_dp_stats = sorted(dp_stats2.items(), key=lambda kv: kv[1])
for k, v in sorted_dp_stats:
    if dp_stats[k] != v:
        print("%d->%d\t%s" % (dp_stats[k], v, k))
    else:
        print("%d\t%s" % (v, k))
print("")

print("Total number: %d" % total_count)

