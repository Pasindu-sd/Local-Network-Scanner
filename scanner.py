import socket
import subprocess

NETWORK = "192.168.8."
PORTS = [21, 22, 23, 53, 80, 443, 3389, 8080]
INTERNET_PORTS = [53, 80, 443, 8080]

BAD_SERVICES = {
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
        if result.returncode == 0:
            return True
        else:
            return False
    except:
        return False


def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return "Unknown"


def scan_ports(ip, ports):
    open_ports = []
    
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            
            result = s.connect_ex((ip, port))
            
            if result == 0:
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
    
    for port in open_ports:
        if port in INTERNET_PORTS:
            score = score + 3
    
    for port in open_ports:
        if port in BAD_SERVICES:
            score = score + 2
    
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
print("\nDNS Resolution Available : " + str(dns_available))
print("-" * 65)

for i in range(1, 255):
    ip = NETWORK + str(i)
    
    if ping_host(ip) == False:
        continue
    
    hostname = get_hostname(ip)
    
    open_ports = scan_ports(ip, PORTS)
    
    risk = calculate_risk(open_ports)
    
    print("IP        : " + ip)
    print("Hostname  : " + hostname)
    
    if len(open_ports) == 0:
        print("OpenPorts : None")
    else:
        print("OpenPorts : " + str(open_ports))
    
    print("Risk      : " + risk)
    
    internet_used = []
    for port in open_ports:
        if port in INTERNET_PORTS:
            internet_used.append(port)
    
    if len(internet_used) > 0 and dns_available == True:
        print("INTERNET ACCESS ATTEMPT DETECTED")
        print("   Ports : " + str(internet_used))
        violators.append(ip)
    
    suspicious = []
    for port in open_ports:
        if port in BAD_SERVICES:
            suspicious.append(port)
    
    if len(suspicious) > 0:
        print("Suspicious Services:")
        for port in suspicious:
            service_name = BAD_SERVICES[port]
            print("   - " + str(port) + " (" + service_name + ")")
    
    print("-" * 65)


print("\nSUMMARY REPORT")
print("=" * 65)

if len(violators) > 0:
    print("PCs Attempting Internet Access:")
    for violator in violators:
        print(" - " + violator)
else:
    print("No Internet Access Violations Detected")

print("\nScan Completed")
