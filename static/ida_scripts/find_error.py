
import sys


f1 = open('paths2.txt', 'r')
f2 = open('paths3.txt', 'r')


f1_paths = []
f2_paths = []

for line in f1:
    line = line.rstrip()
    if line[0] == '+':
        f1_paths.append(line)
for line in f2:
    line = line.rstrip()
    if line[0] == '+':
        f2_paths.append(line)

f1.close()
f2.close()

i = 0

while i < len(f1_paths) and i < len(f2_paths):
    p1 = eval(f1_paths[i][1:])
    p2 = eval(f2_paths[i][1:])

    j = 0
    for addr in p2:
        while p1[j] != addr:
            j += 1
            if j >= len(p1):
                break
        if j == len(p1):
            print("Found error! %d" % i)
            print(p1)
            print(p2)
            sys.exit(0)

    i += 1





