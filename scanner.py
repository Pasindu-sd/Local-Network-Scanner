from utils import ping_host, get_hostname, scan_ports

NETWORK = "192.168.0."
PORTS = [21, 22, 23, 80, 443, 3306]

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
