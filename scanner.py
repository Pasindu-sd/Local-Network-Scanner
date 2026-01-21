import socket
import subprocess
import time

NETWORK = " 192.168.8."

PORTS = [21, 22, 23, 53, 80, 443, 3389, 8080]

INTERNET_PORTS = [53, 80, 443, 8080]

SUSPICIOUS_PORTS = {
    21: "FTP",
    23: "Telnet",
    3389: "RDP"
}


def ping_host(ip):
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "300", ip],
            stdout=subprocess.DEVNULL
        )
        return result.returncode == 0
    except:
        return False


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"


def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except:
            pass
    return open_ports


def dns_test():
    try:
        socket.gethostbyname("google.com")
        return True
    except:
        return False


def calculate_risk(open_ports):
    score = 0
    for p in open_ports:
        if p in INTERNET_PORTS:
            score += 3
        if p in SUSPICIOUS_PORTS:
            score += 2

    if score == 0:
        return "LOW"
    elif score <= 4:
        return "MEDIUM"
    else:
        return "HIGH"


print("=" * 65)
print(" LAB NETWORK INTERNET ATTEMPT DETECTOR (NO SCAPY)")
print(" Blue Team | SOC | University Lab Security ")
print("=" * 65)

violators = []

dns_available = dns_test()

print(f"\nDNS Resolution Available : {dns_available}")
print("-" * 65)

for i in range(1, 255):
    ip = NETWORK + str(i)

    if not ping_host(ip):
        continue

    hostname = get_hostname(ip)
    open_ports = scan_ports(ip, PORTS)
    risk = calculate_risk(open_ports)

    print(f"IP        : {ip}")
    print(f"Hostname  : {hostname}")
    print(f"OpenPorts : {open_ports if open_ports else 'None'}")
    print(f"Risk      : {risk}")

    internet_used = [p for p in open_ports if p in INTERNET_PORTS]

    if internet_used and dns_available:
        print("INTERNET ACCESS ATTEMPT DETECTED")
        print("   Ports :", internet_used)
        violators.append(ip)

    suspicious = [p for p in open_ports if p in SUSPICIOUS_PORTS]
    if suspicious:
        print("Suspicious Services:")
        for p in suspicious:
            print(f"   - {p} ({SUSPICIOUS_PORTS[p]})")

    print("-" * 65)


print("\nSUMMARY REPORT")
print("=" * 65)

if violators:
    print("PCs Attempting Internet Access:")
    for v in violators:
        print(" -", v)
else:
    print("No Internet Access Violations Detected")

print("\nScan Completed")
