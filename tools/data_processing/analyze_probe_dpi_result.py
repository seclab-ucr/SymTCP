import argparse

def read_test_cases(path):
    with open(path, 'r') as fin:
        data = fin.readlines()
    return data

def simple_analyze_results(data, mode):
	success_cases = {}
	if mode == 'ids':
		success_state_ids = {}
	elif mode == 'gfw':
		success_state_ids = set()
	dp_counts = {}
	all_state_ids = set()
	for d in data:
		is_success = False
		fields = eval(d[:-1])
		state_id = fields['state_id']
		all_state_ids.add(state_id)
		if not fields['drop_points']:
			dp = "Evasion"
		else:
			dp = fields['drop_points'][0]
		if dp not in dp_counts:
			dp_counts[dp] = {'total': 1, 'succ': 0}
		else:
			dp_counts[dp]['total'] += 1
		success_cases[state_id] = []
		results = fields['results']
		for num_pkts, tcp_flags in results.items():
			for flag, res in tcp_flags.items():
				if not flag:
					flag = "UNCONSTRAINED"
				if isinstance(res, int):
					continue
				if mode == 'gfw':
					if res['server'] == True:
						for gfw, label in res.items():
							if label == False:
								success_state_ids.add(state_id)
								is_success = True
								res_str = ','.join([state_id, str(num_pkts), flag, '\n'])
								success_cases[state_id].append(res_str)
				elif mode == 'ids':
					if res['apache'] == True:
						for ids, label in res.items():
							if label == False:
								if ids not in success_state_ids:
									success_state_ids[state_id] = {ids}
								else:
									success_state_ids[state_id].add(ids)
								is_success = True
								res_str = ','.join([state_id, str(num_pkts), flag, ids, '\n'])
								success_cases[state_id].append(res_str)
		if is_success:
			dp_counts[dp]['succ'] += 1
	for key in sorted(dp_counts):
		print(key, dp_counts[key], float(dp_counts[key]['succ'] / dp_counts[key]['total']))
	print("Num of successful state ids:", len(success_state_ids))
	print("Num of all state ids:", len(all_state_ids))
	return success_cases, success_state_ids, all_state_ids, dp_counts

def dump_analysis_results(res):
	if args.gfw:
		with open('probe_dpi_res_analysis_gfw.txt', 'w') as fin:
			for state_id, info in res.items():
				fin.writelines(info)
	else:
		with open('probe_dpi_res_analysis_ids.txt', 'w') as fin:
			for state_id, info in res.items():
				fin.writelines(info)

def dump_success_state_ids(success, all):
	if args.gfw:
		with open('probe_dpi_success_analysis_gfw.txt', 'w') as fin:
			fin.write('##SucessStateIds\n')
			for state_id in list(success):
				fin.write(state_id + '\n')
			fin.write('##FailStateIds\n')
			for state_id in list(all - success):
				fin.write(state_id + '\n')
	else:
		with open('probe_dpi_success_analysis_ids.txt', 'w') as fin:
			fin.write('##SucessStateIds\n')
			for state_id in list(success):
				fin.write(state_id + '\n')
			fin.write('##FailStateIds\n')
			for state_id in list(all - success):
				fin.write(state_id + '\n')


parser = argparse.ArgumentParser()
parser.add_argument('-T', "--test-cases")
parser.add_argument('-T2', "--test-cases-2")
parser.add_argument('-G', '--gfw', default=False, action='store_true')
args = parser.parse_args()

test_case_res = read_test_cases(args.test_cases)
if args.test_cases_2:
	test_case_res_2 = read_test_cases(args.test_cases_2)
if args.gfw:
	success_cases, success_state_ids, all_state_ids, drop_points = simple_analyze_results(test_case_res, 'gfw')
	if args.test_cases_2:
		success_cases, success_state_ids, all_state_ids, drop_points_2 = simple_analyze_results(test_case_res_2, 'gfw')
else:
	success_cases, success_state_ids, all_state_ids, drop_points = simple_analyze_results(test_case_res, 'ids')
	if args.test_cases_2:
		success_cases, success_state_ids, all_state_ids, drop_points_2 = simple_analyze_results(test_case_res_2, 'ids')

dump_analysis_results(success_cases)

if args.test_cases_2:
	for key, val in drop_points.items():
		if key not in drop_points_2:
			print(key, "not present in new results!")
		else:
			val_2 = drop_points_2[key]
			if float(val['succ'] / val['total']) > float(val_2['succ'] / val_2['total']):
				print(key)
				print(','.join(['Old', str(val['succ']), str(val['total']), str(float(val['succ'] / val['total']))]))
				print(','.join(['New', str(val_2['succ']), str(val_2['total']), str(float(val_2['succ'] / val_2['total']))]))

dump_success_state_ids(success_state_ids, all_state_ids)