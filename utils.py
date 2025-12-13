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