from utils import ping_host, get_hostname, scan_ports

NETWORK = "192.168.8."
PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080]

SUSPICIOUS_PORTS = {
    21: "FTP (Unencrypted File Transfer)",
    23: "Telnet (Insecure Remote Access)",
    25: "SMTP (Mail Server)",
    53: "DNS Service",
    110: "POP3",
    143: "IMAP",
    445: "SMB File Sharing",
    1433: "MSSQL Database",
    3306: "MySQL Database",
    3389: "RDP Remote Desktop",
    5900: "VNC Remote Access"
}

def detect_suspicious_ports(open_ports):
    found = {}
    for port in open_ports:
        if port in SUSPICIOUS_PORTS:
            found[port] = SUSPICIOUS_PORTS[port]
    return found


print("Local Network Scan Started...\n")

for i in range(1, 255):
    ip = NETWORK + str(i)

    if ping_host(ip):
        hostname = get_hostname(ip)
        open_ports = scan_ports(ip, PORTS)
        suspicious = detect_suspicious_ports(open_ports)

        print(f"IP        : {ip}")
        print(f"Hostname  : {hostname}")

        if open_ports:
            print(f"OpenPorts : {open_ports}")
        else:
            print("OpenPorts : None")

        if suspicious:
            print("⚠️ ALERT : Suspicious Ports Detected")
            for p, desc in suspicious.items():
                print(f"   - Port {p} : {desc}")

        print("-" * 40)
