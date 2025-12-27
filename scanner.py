from utils import ping_host, get_hostname, scan_ports

NETWORK = "192.168.8."
PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080]

print("Local Network Scan Started...\n")

for i in range(1, 255):
    ip = NETWORK + str(i)

    if ping_host(ip):
        hostname = get_hostname(ip)
        open_ports = scan_ports(ip, PORTS)

        print(f"IP        : {ip}")
        print(f"Hostname  : {hostname}")

        if open_ports:
            print(f"OpenPorts : {open_ports}")
        else:
            print("OpenPorts : None")

        print("-" * 40)