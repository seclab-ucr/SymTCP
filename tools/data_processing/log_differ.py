import re
from collections import Counter

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--file1", help="display a square of a given number")
parser.add_argument("--file2", help="display a square of a given number")
parser.add_argument("--detail", action="store_true", default=False)
args = parser.parse_args()

filename_a = args.file1
filename_b = args.file2
print_details = args.detail

ID_PATTERN = r'ultrasurf#\w+#'

def find_bad_keyword_id_one_line(text):
	m = re.search(ID_PATTERN, text)
	if m:
		return m.group(0)
	else:
		#print("[PARSER][error] No Id found in line: ", text)
		return None

def find_all_bad_keyword_ids_one_file(file_dir):
	with open(file_dir, 'r') as fin:
		data = fin.readlines()
	state_ids = []
	for d in data:
		state_id_str = find_bad_keyword_id_one_line(d)
		if state_id_str:
			if args.fuzz_tcpflags:
				state_id_flag = state_id_str.split('#')[1]
				(state_id, flag) = state_id_flag.split('_')
				state_ids.append(int(state_id))
			else:
				state_id = state_id_str.split('#')[1]
				state_ids.append(int(state_id))
	# should not be any duplicate, but nice to double-check
	state_ids = list(set(state_ids))
	return state_ids

file_a_ids = find_all_bad_keyword_ids_one_file(filename_a)
file_a_max_id = max(file_a_ids)
file_a_min_id = min(file_a_ids) 

file_b_ids = find_all_bad_keyword_ids_one_file(filename_b)
file_b_max_id = max(file_b_ids)
file_b_min_id = min(file_b_ids)

id_cut_max = min(file_a_max_id, file_b_max_id)
id_cut_min = max(file_a_min_id, file_b_min_id)

file_a_ids_set = set()
file_b_ids_set = set()

for id in file_a_ids:
    if id < id_cut_min or id > id_cut_max:
        continue
    else:
        file_a_ids_set.add(id)

for id in file_b_ids:
    if id < id_cut_min or id > id_cut_max:
        continue
    else:
        file_b_ids_set.add(id)

print("Size of File_A: ", len(file_a_ids_set))
print("Size of File_B: ", len(file_b_ids_set))
print("Num of File_A - File_B", len(file_a_ids_set - file_b_ids_set))
print("Num of File_B - File_A", len(file_b_ids_set - file_a_ids_set))
print("Num of intersection:", len(file_a_ids_set.intersection(file_b_ids_set)))

if print_details:
    with open('diff_details', 'w') as fout:
        fout.write('##Only in A\n')
        fout.writelines(map(lambda l: str(l) + '\n', list(file_a_ids_set - file_b_ids_set)))
        fout.write("##Only in B\n")
        fout.writelines(map(lambda l: str(l) + '\n', list(file_b_ids_set - file_a_ids_set)))
