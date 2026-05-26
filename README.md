
# Local-Network-Scanner
Building a tool that detects devices on a home/lab network. IP, MAC address, open ports, OS identification, etc.


---

Using 

```
pip install colorama beautifulsoup4 requests

# Scan your local network
python local_network_scanner.py -t 192.168.1.0/24

# Scan HTB machine (after VPN connect)
python local_network_scanner.py -t 10.129.x.x

# Fast scan only
python local_network_scanner.py -t 192.168.1.0/24 --fast

# Save results
python local_network_scanner.py -t 192.168.1.0/24 --json results.json

```
=======
# Local Network Scanner

Simple Python-based Local Network Scanner.

## Features
- Ping sweep
- Hostname detection
- Basic port scanning

## Run
```bash
python scanner.py
