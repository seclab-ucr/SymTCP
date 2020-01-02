import socket

host_ip_addrs = []

with open("domains.txt", 'r') as fin:
	domains = fin.readlines()

for domain in domains:
	url = domain.strip()
	host_ip = socket.gethostbyname(url)
	print("IP addr of", url, ":", host_ip)
	host_ip_addrs.append(host_ip + '\n')

with open("server_list", 'w') as fout:
	fout.writelines(host_ip_addrs)
