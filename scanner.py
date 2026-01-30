import socket
import subprocess

# Settings for network scan
NETWORK = "192.168.8."
PORTS = [21, 22, 23, 53, 80, 443, 3389, 8080]
INTERNET_PORTS = [53, 80, 443, 8080]

# Bad services we want to find
BAD_SERVICES = {
    21: "FTP",
    23: "Telnet",
    3389: "RDP"
}


# Function to ping an IP address
def ping_host(ip):
    try:
        # Run ping command
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "300", ip],
            stdout=subprocess.DEVNULL
        )
        # If ping works, return True
        if result.returncode == 0:
            return True
        else:
            return False
    except:
        # If error, return False
        return False


# Function to get hostname from IP
def get_hostname(ip):
    try:
        # Try to get hostname
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        # If fails, return Unknown
        return "Unknown"


# Function to check if a port is open
def scan_ports(ip, ports):
    open_ports = []
    
    # Check each port one by one
    for port in ports:
        try:
            # Create socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            
            # Try to connect to port
            result = s.connect_ex((ip, port))
            
            # If connection works, port is open
            if result == 0:
                open_ports.append(port)
            
            # Close socket
            s.close()
        except:
            # Skip if error
            pass
    
    return open_ports


# Function to check if DNS works
def dns_test():
    try:
        # Try to resolve google.com
        socket.gethostbyname("google.com")
        return True
    except:
        return False


# Function to calculate risk level
def calculate_risk(open_ports):
    score = 0
    
    # Add score for internet ports
    for port in open_ports:
        if port in INTERNET_PORTS:
            score = score + 3
    
    # Add score for suspicious ports
    for port in open_ports:
        if port in BAD_SERVICES:
            score = score + 2
    
    # Return risk level based on score
    if score == 0:
        return "LOW"
    elif score <= 4:
        return "MEDIUM"
    else:
        return "HIGH"


# Main program starts here
print("=" * 65)
print(" LAB NETWORK INTERNET ATTEMPT DETECTOR (NO SCAPY)")
print(" Blue Team | SOC | University Lab Security ")
print("=" * 65)

# List to store computers that use internet
violators = []

# Check if DNS works
dns_available = dns_test()
print("\nDNS Resolution Available : " + str(dns_available))
print("-" * 65)

# Scan each IP address
for i in range(1, 255):
    ip = NETWORK + str(i)
    
    # Check if computer is online
    if ping_host(ip) == False:
        continue
    
    # Get computer name
    hostname = get_hostname(ip)
    
    # Scan ports
    open_ports = scan_ports(ip, PORTS)
    
    # Calculate risk
    risk = calculate_risk(open_ports)
    
    # Print results
    print("IP        : " + ip)
    print("Hostname  : " + hostname)
    
    if len(open_ports) == 0:
        print("OpenPorts : None")
    else:
        print("OpenPorts : " + str(open_ports))
    
    print("Risk      : " + risk)
    
    # Check for internet usage
    internet_used = []
    for port in open_ports:
        if port in INTERNET_PORTS:
            internet_used.append(port)
    
    # If using internet, mark as violator
    if len(internet_used) > 0 and dns_available == True:
        print("INTERNET ACCESS ATTEMPT DETECTED")
        print("   Ports : " + str(internet_used))
        violators.append(ip)
    
    # Check for suspicious services
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


# Print summary
print("\nSUMMARY REPORT")
print("=" * 65)

if len(violators) > 0:
    print("PCs Attempting Internet Access:")
    for violator in violators:
        print(" - " + violator)
else:
    print("No Internet Access Violations Detected")

print("\nScan Completed")
