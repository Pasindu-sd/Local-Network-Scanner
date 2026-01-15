import socket
import subprocess
import ipaddress

NETWORK = "192.168.56."

PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443,
    465, 587, 993, 995, 1433, 3306,
    3389, 5900, 8080
]

INTERNET_PORTS = [80, 443, 8080]

SUSPICIOUS_PORTS = {
    21: "FTP (Unencrypted)",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    110: "POP3",
    143: "IMAP",
    3389: "RDP",
    5900: "VNC"
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
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except:
            pass
    return open_ports


def detect_internet_attempt(open_ports):
    found = []
    for p in open_ports:
        if p in INTERNET_PORTS:
            found.append(p)
    return found


def calculate_risk(suspicious, internet_ports):
    score = len(suspicious) * 2 + len(internet_ports) * 3

    if score == 0:
        return "LOW"
    elif score <= 4:
        return "MEDIUM"
    else:
        return "HIGH"



print("=" * 60)
print(" LAB NETWORK - INTERNET ACCESS VIOLATION SCANNER ")
print("=" * 60)
print()

violators = []

for i in range(1, 255):
    ip = NETWORK + str(i)

    if not ping_host(ip):
        continue

    hostname = get_hostname(ip)
    open_ports = scan_ports(ip, PORTS)
    internet_ports = detect_internet_attempt(open_ports)

    suspicious = {p: SUSPICIOUS_PORTS[p] for p in open_ports if p in SUSPICIOUS_PORTS}

    risk = calculate_risk(suspicious, internet_ports)

    print(f"IP        : {ip}")
    print(f"Hostname  : {hostname}")
    print(f"OpenPorts : {open_ports if open_ports else 'None'}")
    print(f"Risk Level: {risk}")

    if internet_ports:
        print("INTERNET ACCESS ATTEMPT DETECTED")
        print(f"   Ports  : {internet_ports}")
        violators.append(ip)

    if suspicious:
        print("Suspicious Services:")
        for p, d in suspicious.items():
            print(f"   - {p} ({d})")

    print("-" * 60)


print("\nSUMMARY REPORT")
print("=" * 60)

if violators:
    print("PCs Attempting Internet Access:")
    for v in violators:
        print(" -", v)
else:
    print("No Internet Access Violations Detected")

print("\nScan Finished ✔")
