import socket
import subprocess

def ping_host(ip):
   result = subprocess.run(["ping", "-n", "1", "-w", "300", ip], stdout=subprocess.DEVNULL)   
   return result.returncode == 0

def egt_hostname(ip):
   try:
      return socket.gethostbyaddr(ip)[0]
   except:
      return "Unknown"
   
def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        if s.connect_ex((ip, port)) == 0:
            open_ports.append(port)
        s.close()
    return open_ports
