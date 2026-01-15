import socket
import subprocess

NETWORK = "10.202.83."
PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443,
    465, 587, 993, 995, 1433, 1521, 3306,
    3389, 5432, 5900, 8080
]

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


def internet_access_check():
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "300", "8.8.8.8"],
            stdout=subprocess.DEVNULL
        )
        return result.returncode == 0
    except:
        return False


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


def detect_suspicious_ports(open_ports):
    found = {}
    for port in open_ports:
        if port in SUSPICIOUS_PORTS:
            found[port] = SUSPICIOUS_PORTS[port]
    return found


def calculate_risk(suspicious_ports, internet_enabled):
    score = len(suspicious_ports)

    if internet_enabled:
        score += 2 

    if score == 0:
        return "LOW"
    elif score <= 2:
        return "MEDIUM"
    else:
        return "HIGH"



print("=" * 42)
print("   LOCAL NETWORK & LAB SECURITY SCANNER")
print("=" * 42)

print("\n[+] Checking Internet Access Status...\n")

internet_enabled = internet_access_check()

if internet_enabled:
    print("[VIOLATION] Internet access is ENABLED in LAB NETWORK")
else:
    print("[OK] Internet access is BLOCKED (Lab Safe)")

print("\nStarting Local Network Scan...\n")

for i in range(1, 255):
    ip = NETWORK + str(i)

    if not ping_host(ip):
        continue

    open_ports = scan_ports(ip, PORTS)
    hostname = get_hostname(ip)
    suspicious = detect_suspicious_ports(open_ports)

    print(f"IP        : {ip}")
    print(f"Hostname  : {hostname}")
    print(f"OpenPorts : {open_ports if open_ports else 'None'}")
    print(f"Risk Level: {calculate_risk(suspicious, internet_enabled)}")

    if suspicious:
        print("⚠ ALERT : Suspicious Services Detected")
        for p, desc in suspicious.items():
            print(f"   - Port {p} : {desc}")

    print("-" * 50)

print("\nScan Completed")