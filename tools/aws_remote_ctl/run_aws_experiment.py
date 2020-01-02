import os, time
import subprocess
import argparse

linux_usrname = 'username'
linux_passwd = 'password'

server_name = 'yourhttpserver'

def read_ec2_instances_urls(filename):
	print("[IMPORTANT] AWS EC2 IP ADDR LIST FILANAME: ", filename)
	raw_input("Press ENTER to continue...")
	urls = []
	with open(filename, 'r') as fin:
		data = fin.readlines()
	for d in data:
		url = d.strip()
		if url:
			urls.append(url)
	return urls

# uses screen sessions
def generate_detached_ssh_cmd(cmd, url):
	cmd_from_local = ' '.join(["screen", "-S", "test", "-dm", "bash", "-c", cmd])
	cmd_from_local = '"' + cmd_from_local + '"'
	cmd_to_ssh = ' '.join(["ssh", "-o", "'StrictHostKeyChecking=no'", "-i", args.pem_file, '@'.join([linux_usrname, url]), cmd_from_local])
	return cmd_to_ssh

def generate_sync_ssh_cmd(cmd, url):
	cmd_from_local = ' '.join(["bash", "-c", cmd])
	cmd_from_local = '"' + cmd_from_local + '"'
	cmd_to_ssh = ' '.join(["ssh", "-o", "'StrictHostKeyChecking=no'", "-i", args.pem_file, '@'.join([linux_usrname, url]), cmd_from_local])
	return cmd_to_ssh

def generate_sync_scp_cmd(remote_fname, local_dir, url):
	linux_cred = '@'.join([linux_usrname, url])
	remote = ':'.join([linux_cred, remote_fname])
	cmd_to_scp = ' '.join(["scp", "-o", "'StrictHostKeyChecking=no'", "-i", args.pem_file, remote, local_dir])
	return cmd_to_scp

def run_local_exp(urls, data_fname, payload_length):
	for i in range(len(urls)):
		url = urls[i]
		time.sleep(1)
		local_cmd = "'cd sym-tcp/scripts && sudo bash run_local_experiment.sh %s %d %d %d'" % (data_fname, len(urls), i, payload_length)
		cmd = generate_detached_ssh_cmd(local_cmd, url)
		print("[Local] Exec cmd: " + cmd)
		subprocess.call(cmd, shell=True)

def run_gfw_exp(urls, data_fname, payload_length):
	for i in range(len(urls)):
		url = urls[i]
		time.sleep(1)
		local_cmd = "'cd sym-tcp/scripts && sudo python probe_dpi.py -P -G -F -I eth0 -N %d -S %d -p %d ~/%s'" % (len(urls), i, payload_length, data_fname)
		cmd = generate_detached_ssh_cmd(local_cmd, url)
		print("[GFW] Exec cmd: " + cmd)
		subprocess.call(cmd, shell=True)

def update_repo(urls):
	for i in range(len(urls)):
		url = urls[i]
		local_cmd = "'cd sym-tcp && git pull https://github.com/seclab-ucr/sym-tcp.git'"
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Pull] Exec cmd: " + cmd)
		subprocess.Popen(cmd, shell=True)

def reclone_repo(urls):
	for i in range(len(urls)):
		url = urls[i]
		local_cmd = "'sudo rm -rf sym-tcp && git clone https://github.com/seclab-ucr/sym-tcp.git'"
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Reclone] Exec cmd: " + cmd)
		subprocess.Popen(cmd, shell=True)

def kill_processes(urls):
	for i in range(len(urls)):
		url = urls[i]
		# killing bash/Python should kill all processes
		# as specified in the bash/Python script
		local_cmd = "'sudo pkill bash && sudo pkill python'"
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Kill] Exec cmd: " + cmd)
		subprocess.Popen(cmd, shell=True)

def clean_log(urls):
	for i in range(len(urls)):
		url = urls[i]
		local_cmd = "'cd sym-tcp/scripts && sudo bash collect_log_files.sh'"
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Clean] Exec cmd: " + cmd)
		subprocess.Popen(cmd, shell=True)

def display_ps(urls):
	for i in range(len(urls)):
		url = urls[i]
		local_cmd = "'ps -a'"
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Ps] Exec cmd: " + cmd)
		subprocess.call(cmd, shell=True)

def replace_snort_confs(urls):
	for i in range(len(urls)):
		url = urls[i]
		local_cmd = "'sudo rm -rf /etc/snort/ && sudo cp sym-tcp/tools/dpi_sys_confs/snort/ /etc/ -r'"
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Ps] Exec cmd: " + cmd)
		subprocess.Popen(cmd, shell=True)

def unzip_data(urls, data_path, data_fname):
	for i in range(len(urls)):
		url = urls[i]
		local_cmd = "'cd sym-tcp/data/ && tar -xvzf %s/%s.tar.gz'" % (data_path, data_fname)
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Data] Exec cmd: " + cmd)
		subprocess.Popen(cmd, shell=True)

def delete_apache_log(urls):
	for i in range(len(urls)):
		url = urls[i]
		local_cmd = "'sudo rm /var/log/apache2/access.log'"
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Apache] Exec cmd: " + cmd)
		subprocess.Popen(cmd, shell=True)

def download_local_logs(urls, data_dir):
	for i in range(len(urls)):
		url = urls[i]
		local_cmd = "'cd sym-tcp && sudo chown -R %s: logs'" % linux_usrname
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Download-Local-0] Exec cmd: " + cmd)
		subprocess.Popen(cmd, shell=True)

	raw_input("Press ENTER to continue...")

	for i in range(len(urls)):
		url = urls[i]
		cmd_lst = []
		cmd_lst.append("cd sym-tcp/logs")
		for fname in ["apache.log.2019", "bro.log.2019", 'probe_dpi.log', 'probe_dpi_result.2019']:
			cmd_lst.append('mv %s* %s.log.%s' % (fname, fname, str(i)))
		local_cmd = '\'' +  ' && '.join(cmd_lst) + '\''
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Download-Local-1-1] Exec cmd: " + cmd)
		subprocess.Popen(cmd, shell=True)

	raw_input("Press ENTER to continue...")

	# splited due to some bash bug I don't know why...
	for i in range(len(urls)):
		url = urls[i]
		cmd_lst = []
		cmd_lst.append("cd sym-tcp/logs")
		for fname in ["snort", "netfilter"]:
			cmd_lst.append('tshark -r %s* > processed_%s.log.%s' % (fname, fname, str(i)))
		cmd_lst.append("sudo chown %s: processed_snort*" % linux_usrname)
		local_cmd = '\'' +  ' && '.join(cmd_lst) + '\''
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Download-Local-1-2] Exec cmd: " + cmd)
		subprocess.Popen(cmd, shell=True)

	raw_input("Press ENTER to continue...")

	for i in range(len(urls)):
		url = urls[i]
		log_zip_fname = 'logs.tar.gz.local.' + str(i)
		local_cmd = '\'' +  "tar -zcvf %s sym-tcp/logs" % (log_zip_fname) + '\''
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Download-Local-2] Exec cmd: " + cmd)
		subprocess.Popen(cmd, shell=True)

	raw_input("Press ENTER to continue...")

	for i in range(len(urls)):
		url = urls[i]
		log_zip_fname = 'logs.tar.gz.local.' + str(i)
		cmd = generate_sync_scp_cmd('/home/ubuntu/' + log_zip_fname, data_dir, url)
		print("[Download-Local-3] Exec cmd: " + cmd)
		subprocess.Popen(cmd, shell=True)

	raw_input("Press ENTER to continue...")

def download_pcaps(urls, mode, data_dir):
	for i in range(len(urls)):
		url = urls[i]
		cmd_lst = []
		if mode == 'gfw':
			cmd_lst.append("sudo cp sym-tcp/scripts/probe_dpi_result sym-tcp/scripts/pcaps/probe_dpi_result.log.%d && sudo cp sym-tcp/scripts/probe_dpi.log sym-tcp/scripts/pcaps/probe_dpi.log.%d" % (i, i))
		log_zip_fname = 'pcaps.tar.gz.%s.%s' % (mode, str(i))
		cmd_lst.append("sudo tar -zcf %s sym-tcp/scripts/pcaps" % log_zip_fname)
		local_cmd = '\'' +  ' && '.join(cmd_lst) + '\''
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Download-PCAP-1] Exec cmd: " + cmd)
		subprocess.Popen(cmd, shell=True)

	raw_input("Press ENTER to continue...")

	for i in range(len(urls)):
		url = urls[i]
		log_zip_fname = 'pcaps.tar.gz.%s.%s' % (mode, str(i))
		cmd = generate_sync_scp_cmd('/home/ubuntu/' + log_zip_fname, data_dir, url)
		print("[Download-PCAP-2] Exec cmd: " + cmd)
		subprocess.Popen(cmd, shell=True)

def merge_logs(log_type, log_dir):
	log_fnames = []
	cmd_lst = ['cd %s' % log_dir]
	for filename in os.listdir(log_dir):
		if filename.startswith(log_type):
			log_fnames.append(filename)
	cmd_lst.append('cat ' + ' '.join(log_fnames) + ' > %s.log' % log_type)
	cmd = ' && '.join(cmd_lst)
	print("[Merge] Exec cmd: " + cmd)
	subprocess.call(cmd, shell=True)
	return

def process_downloaded_data(data_dir, mode):
	print("[IMPORTANT] LOCAL DATA DIR: ", data_dir)
	raw_input("Press ENTER to continue...")
	cmd_lst = ['cd %s' % data_dir]
	log_types = ['processed_snort', 'bro', 'processed_netfilter', 'probe_dpi.log', 'apache', 'probe_dpi_result']
	for filename in os.listdir(data_dir):
		if mode == 'local':
			if filename.startswith('logs.tar.gz') or (filename.startswith('pcaps.tar.gz') and 'local' in filename):
				cmd_lst.append('tar -xvzf %s' % filename)
		if mode == 'gfw':
			if filename.startswith('pcaps.tar.gz') and 'gfw' in filename:
				cmd_lst.append('tar -xvzf %s' % filename)
	cmd = '&&'.join(cmd_lst)
	print("[Log-Processing] Exec cmd: " + cmd)
	subprocess.call(cmd, shell=True)

	if mode == 'local':
		for log_type in log_types:
			merge_logs(log_type, data_dir + '/sym-tcp/logs')
	if mode == 'gfw':
		for log_type in ['probe_dpi.log', 'probe_dpi_result']:
			merge_logs(log_type, data_dir + '/sym-tcp/scripts/pcaps')

def download_test_cases(urls, data_fname):
	for i in range(len(urls)):
		url = urls[i]
		local_cmd = "'rm -rf tmpdata && mkdir tmpdata && cd tmpdata && wget %s/%s && tar zxvf %s && rm %s && mv * ~/ && cd .. && rm -r tmpdata'" % (server_name, data_fname, data_fname, data_fname)
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Data] Exec cmd: " + cmd)
		subprocess.call(cmd, shell=True)

def unzip_test_cases(urls, data_fname):
	for i in range(len(urls)):
		url = urls[i]
		local_cmd = "'cd tmpdata && tar zxvf %s && mv * ~/ && cd .. && rm -r tmpdata'" % (data_fname)
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Data] Exec cmd: " + cmd)
		subprocess.call(cmd, shell=True)

def delete_logs(urls):
	for i in range(len(urls)):
		url = urls[i]
		local_cmd = "'cd ~/sym-tcp/logs/ && sudo rm apache* && sudo rm bro* && rm probe_dpi* && sudo rm processed* && sudo rm snort*'"
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Data] Exec cmd: " + cmd)
		subprocess.Popen(cmd, shell=True)

def delete_pcaps(urls):
	for i in range(len(urls)):
		url = urls[i]
		local_cmd = "'cd sym-tcp/scripts && sudo rm -rf pcaps && sudo rm probe_dpi_result.log'"
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Data] Exec cmd: " + cmd)
		subprocess.Popen(cmd, shell=True)

def run_cmd(urls, command):
	for i in range(len(urls)):
		url = urls[i]
		local_cmd = "'%s'" % command
		cmd = generate_sync_ssh_cmd(local_cmd, url)
		print("[Data] Exec cmd: " + cmd)
		subprocess.call(cmd, shell=True)
                time.sleep(1)


parser = argparse.ArgumentParser(description='AWS remote control whole-family-bucket')
parser.add_argument('-P', dest='pem_file', default='sym_tcp.pem', type=str)
parser.add_argument('-U', dest='url_list', default='aws_url_list_20byte', type=str)
parser.add_argument('-DF', dest='data_fname', type=str)
parser.add_argument('-DP', dest='data_path', type=str)
parser.add_argument('-PL', dest='payload_length', type=int)
parser.add_argument('-LDD', dest='local_data_dir', type=str)
parser.add_argument('-L', '--local-exp', default=False, action='store_true')
parser.add_argument('-G', '--gfw-exp', default=False, action='store_true')
parser.add_argument('-R', '--update-repo', default=False, action='store_true')
parser.add_argument('-C', '--clean-log', default=False, action='store_true')
parser.add_argument('-RC', '--reclone', default=False, action='store_true')
parser.add_argument('-K', '--kill', default=False, action='store_true')
parser.add_argument('-PS', '--ps', default=False, action='store_true')
parser.add_argument('-UN', '--unzip', default=False, action='store_true')
parser.add_argument('-S', '--snort', default=False, action='store_true')
parser.add_argument('-DL', '--download-local', default=False, action='store_true')
parser.add_argument('-DG', '--download-gfw', default=False, action='store_true')
parser.add_argument('-DA', '--delete-apache', default=False, action='store_true')
parser.add_argument('-PDL', '--process-data-local', default=False, action='store_true')
parser.add_argument('-PDG', '--process-data-gfw', default=False, action='store_true')
parser.add_argument('--delete-logs', default=False, action='store_true')
parser.add_argument('--delete-pcaps', default=False, action='store_true')
parser.add_argument('--download-test-cases', type=str)
parser.add_argument('--unzip-test-cases', type=str)
parser.add_argument('--run-cmd', type=str)
parser.add_argument('--local', default=False, action='store_true')
parser.add_argument('--gfw', default=False, action='store_true')
args = parser.parse_args()

urls = read_ec2_instances_urls(args.url_list)
parsing_gfw = False
urls_local, urls_gfw = [], []
for url in urls:
	if url.startswith('##GFW'):
		parsing_gfw = True
		continue
	if len(url.split(' ')) > 1:
		id, addr = url.split(' ')
		if parsing_gfw:
			urls_gfw.append(addr)
		else:
			urls_local.append(addr)

print("Num of [Local] group:", len(urls_local))
print("Num of [GFW] group:", len(urls_gfw))

urls = []
if not args.gfw and not args.local:
    urls = urls_local + urls_gfw
else:
    if args.local:
        urls += urls_local
    if args.gfw:
        urls += urls_gfw

if args.local_exp:
	run_local_exp(urls_local, args.data_fname, args.payload_length)
if args.gfw_exp:
	run_gfw_exp(urls_gfw, args.data_fname, args.payload_length)
if args.update_repo:
	update_repo(urls)
if args.clean_log:
	clean_log(urls_local)
if args.reclone:
	reclone_repo(urls)
if args.kill:
	kill_processes(urls)
if args.ps:
	display_ps(urls)
if args.unzip:
	unzip_data(urls, args.data_path, args.data_fname)
if args.snort:
	replace_snort_confs(urls)
if args.download_local:
	download_local_logs(urls_local, args.local_data_dir)
	download_pcaps(urls_local, 'local', args.local_data_dir)
if args.download_gfw:
	download_pcaps(urls_gfw, 'gfw', args.local_data_dir)
if args.delete_apache:
	delete_apache_log(urls_local)
if args.process_data_local:
	process_downloaded_data(args.local_data_dir, 'local')
if args.process_data_gfw:
	process_downloaded_data(args.local_data_dir, 'gfw')
if args.download_test_cases:
	download_test_cases(urls, args.download_test_cases)
if args.unzip_test_cases:
	unzip_test_cases(urls, args.download_test_cases)
if args.delete_logs:
	delete_logs(urls_local)
if args.delete_pcaps:
	delete_pcaps(urls)
if args.run_cmd:
	run_cmd(urls, args.run_cmd)

