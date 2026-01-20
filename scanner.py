import socket
import subprocess
import threading
from datetime import datetime

from scapy.all import sniff, IP, UDP, DNS, DNSQR

# ================= CONFIG =================

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

# ================= NETWORK SCANNER =================

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


def detect_internet_capability(open_ports):
    return [p for p in open_ports if p in INTERNET_PORTS]


def calculate_risk(suspicious, internet_ports):
    score = len(suspicious) * 2 + len(internet_ports) * 3
    if score == 0:
        return "LOW"
    elif score <= 4:
        return "MEDIUM"
    else:
        return "HIGH"


def run_network_scan():
    print("\n" + "=" * 65)
    print("   MODULE 1 : LOCAL NETWORK RISK SCANNER")
    print("=" * 65)

    violators = []

    for i in range(1, 255):
        ip = NETWORK + str(i)

        if not ping_host(ip):
            continue

        hostname = get_hostname(ip)
        open_ports = scan_ports(ip, PORTS)
        internet_ports = detect_internet_capability(open_ports)

        suspicious = {
            p: SUSPICIOUS_PORTS[p]
            for p in open_ports if p in SUSPICIOUS_PORTS
        }

        risk = calculate_risk(suspicious, internet_ports)

        print(f"\nIP        : {ip}")
        print(f"Hostname  : {hostname}")
        print(f"OpenPorts : {open_ports if open_ports else 'None'}")
        print(f"RiskLevel : {risk}")

        if internet_ports:
            print("⚠ POTENTIAL INTERNET ACCESS CAPABILITY")
            print(f"   Ports  : {internet_ports}")
            violators.append(ip)

        if suspicious:
            print("⚠ Suspicious Services:")
            for p, d in suspicious.items():
                print(f"   - {p} ({d})")

    print("\n" + "-" * 65)
    print("Scanner Summary")
    if violators:
        for v in violators:
            print(" -", v)
    else:
        print(" No risky hosts detected")
    print("-" * 65)


# ================= DNS MONITOR =================

def is_local_domain(domain):
    return domain.endswith((".local", ".arpa", ".lan"))


def dns_packet_handler(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        domain = packet[DNSQR].qname.decode(errors="ignore").strip(".")
        if is_local_domain(domain):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print("\n🚫 REAL INTERNET ATTEMPT DETECTED (DNS)")
        print(f"   Time      : {time}")
        print(f"   Source PC : {src_ip}")
        print(f"   DNS Server: {dst_ip}")
        print(f"   Domain    : {domain}")
        print("-" * 65)


def start_dns_monitor():
    print("\n" + "=" * 65)
    print("   MODULE 2 : REAL INTERNET ACTIVITY MONITOR (DNS)")
    print("   Listening on UDP port 53...")
    print("=" * 65 + "\n")

    sniff(
        filter="udp port 53",
        prn=dns_packet_handler,
        store=False
    )


# ================= MAIN =================

print("=" * 65)
print(" LAB NETWORK INTERNET ACCESS MONITORING SYSTEM ")
print(" Blue Team | SOC | University Lab Security ")
print("=" * 65)

# Run scanner once
run_network_scan()

# Start DNS monitor in live mode
print("\nStarting LIVE DNS Monitoring (Press CTRL+C to stop)...")
start_dns_monitor()
