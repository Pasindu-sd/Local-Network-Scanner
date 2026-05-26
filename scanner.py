#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   Local Network Scanner v2.0                                 ║
║   Author : PasinduSD | github.com/Pasindu-sd                ║
║   Improved: Banner grabbing + OS fingerprinting via TTL     ║
╚══════════════════════════════════════════════════════════════╝

WHAT'S NEW in v2.0:
  ✅ Banner grabbing   — detect exact service version
  ✅ OS fingerprinting — guess OS from TTL value
  ✅ Service detection — identify service by port + banner
  ✅ HTTP detection    — grab web server info
  ✅ SMB detection     — detect Windows file shares
  ✅ SSH detection     — grab SSH version
  ✅ FTP detection     — check anonymous login
  ✅ Color output      — easy to read results
  ✅ JSON export       — save results for later
  ✅ Progress bar      — see scan progress

USAGE:
  # Scan single host
  python local_network_scanner.py -t 192.168.1.1

  # Scan network range
  python local_network_scanner.py -t 192.168.1.0/24

  # Scan specific ports
  python local_network_scanner.py -t 192.168.1.1 -p 22,80,443,8080

  # Fast scan (common ports only)
  python local_network_scanner.py -t 192.168.1.0/24 --fast

  # Save results to JSON
  python local_network_scanner.py -t 192.168.1.0/24 --json results.json

  # Verbose output
  python local_network_scanner.py -t 192.168.1.1 -v
"""

import argparse
import ipaddress
import json
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    # Fallback if colorama not installed
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = BLUE = ""
    class Style:
        RESET_ALL = BRIGHT = ""
    HAS_COLOR = False

VERSION = "2.0"

BANNER = f"""
{Fore.CYAN}
 _   _      _                      _      
| \\ | | ___| |___      _____  _ __| | __  
|  \\| |/ _ \\ __\\ \\ /\\ / / _ \\| '__| |/ /  
| |\\  |  __/ |_ \\ V  V / (_) | |  |   <   
|_| \\_|\\___|\\__| \\_/\\_/ \\___/|_|  |_|\\_\\  
 ____                                      
/ ___|  ___ __ _ _ __  _ __   ___ _ __    
\\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|   
 ___) | (_| (_| | | | | | | |  __/ |      
|____/ \\___\\__,_|_| |_|_| |_|\\___|_|      
{Style.RESET_ALL}
{Fore.GREEN} Local Network Scanner v{VERSION} — by PasinduSD{Style.RESET_ALL}
"""

# ═══════════════════════════════════════════════════════════════
# COMMON PORTS
# ═══════════════════════════════════════════════════════════════

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 8888, 27017,
]

FAST_PORTS = [21, 22, 23, 80, 443, 445, 3306, 3389, 8080]

# Port → Service name mapping
PORT_SERVICES = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    111:   "RPC",
    135:   "MSRPC",
    139:   "NetBIOS",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    993:   "IMAPS",
    995:   "POP3S",
    1723:  "PPTP",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "HTTP-Alt",
    27017: "MongoDB",
}

# TTL → OS fingerprinting
# Different OS have different default TTL values
TTL_OS_MAP = [
    (64,  "Linux / macOS / Unix"),
    (128, "Windows"),
    (255, "Cisco IOS / Network Device"),
    (60,  "HP-UX"),
    (30,  "Unknown/Custom"),
]


# ═══════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════

@dataclass
class ServiceInfo:
    port:        int
    state:       str         = "closed"
    name:        str         = "unknown"
    version:     str         = ""
    banner:      str         = ""
    extra:       str         = ""


@dataclass
class HostInfo:
    ip:           str
    hostname:     str         = ""
    is_up:        bool        = False
    ttl:          int         = 0
    os_guess:     str         = "Unknown"
    mac:          str         = ""
    open_ports:   List[ServiceInfo] = field(default_factory=list)
    scan_time:    str         = field(default_factory=lambda: datetime.now().isoformat())


# ═══════════════════════════════════════════════════════════════
# OS FINGERPRINTING VIA TTL
# ═══════════════════════════════════════════════════════════════

class OSFingerprinter:
    """Guess OS from TTL value returned by ping"""

    def guess_os_from_ttl(self, ttl: int) -> str:
        """
        TTL fingerprinting — each OS has a different default TTL.
        TTL decrements by 1 at each router hop, so we round up.

        Common defaults:
          Linux/macOS: 64
          Windows:     128
          Cisco IOS:   255
        """
        if ttl <= 0:
            return "Unknown"

        # Round TTL up to nearest common value
        if ttl <= 64:
            return "Linux / macOS / Unix (TTL≤64)"
        elif ttl <= 128:
            return "Windows (TTL≤128)"
        elif ttl <= 255:
            return "Network Device / Cisco IOS (TTL≤255)"
        else:
            return f"Unknown (TTL={ttl})"

    def ping_host(self, ip: str, timeout: int = 1) -> Tuple[bool, int]:
        """
        Ping host and extract TTL from response.
        Returns (is_up, ttl)
        """
        system = platform.system().lower()

        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), ip]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 2,
            )

            output = result.stdout + result.stderr

            # Check if host responded
            if result.returncode != 0:
                return False, 0

            # Extract TTL from ping output
            ttl = self._extract_ttl(output)
            return True, ttl

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False, 0

    def _extract_ttl(self, ping_output: str) -> int:
        """Extract TTL value from ping output string"""
        # Different OS output formats:
        # Linux:   "ttl=64"
        # Windows: "TTL=128"
        # macOS:   "ttl=64"
        patterns = [
            r"ttl=(\d+)",
            r"TTL=(\d+)",
            r"TTL (\d+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, ping_output, re.IGNORECASE)
            if match:
                return int(match.group(1))
        return 0


# ═══════════════════════════════════════════════════════════════
# BANNER GRABBER
# ═══════════════════════════════════════════════════════════════

class BannerGrabber:
    """
    Grab service banners from open ports.
    Banner = first response from service when connected.
    Reveals: software name, version, OS info.
    """

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    def grab(self, ip: str, port: int) -> Tuple[str, str]:
        """
        Connect to port and grab banner.
        Returns (banner_raw, service_version)
        """
        # Use protocol-specific grabbers
        grabbers = {
            21:  self._grab_ftp,
            22:  self._grab_ssh,
            23:  self._grab_telnet,
            25:  self._grab_smtp,
            80:  self._grab_http,
            110: self._grab_pop3,
            143: self._grab_imap,
            443: self._grab_https,
            445: self._grab_smb,
            3306: self._grab_mysql,
            6379: self._grab_redis,
            8080: self._grab_http,
            8443: self._grab_https,
        }

        grabber = grabbers.get(port, self._grab_generic)
        try:
            return grabber(ip, port)
        except Exception:
            return "", ""

    def _raw_connect(self, ip: str, port: int, send: bytes = None) -> str:
        """Generic TCP connect and receive"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            if send:
                sock.send(send)
            data = sock.recv(1024)
            sock.close()
            return data.decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""

    def _grab_generic(self, ip: str, port: int) -> Tuple[str, str]:
        """Generic banner grab — connect and read"""
        banner = self._raw_connect(ip, port)
        version = self._extract_version(banner)
        return banner[:200], version

    def _grab_ftp(self, ip: str, port: int) -> Tuple[str, str]:
        """FTP banner + anonymous login check"""
        banner = self._raw_connect(ip, port)
        if not banner:
            return "", ""

        version = ""
        extra   = ""

        # Extract FTP software version
        # Common: "220 (vsFTPd 3.0.3)" or "220 ProFTPD 1.3.5"
        match = re.search(r"220[- ](.+)", banner)
        if match:
            version = match.group(1).strip()

        # Check anonymous login
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            sock.recv(1024)  # banner
            sock.send(b"USER anonymous\r\n")
            resp = sock.recv(1024).decode("utf-8", errors="ignore")
            if "331" in resp:  # 331 = send password
                sock.send(b"PASS anonymous@\r\n")
                resp2 = sock.recv(1024).decode("utf-8", errors="ignore")
                if "230" in resp2:  # 230 = login successful
                    extra = "⚠️  ANONYMOUS LOGIN ALLOWED!"
            sock.close()
        except Exception:
            pass

        full = f"{version} {extra}".strip()
        return banner[:200], full

    def _grab_ssh(self, ip: str, port: int) -> Tuple[str, str]:
        """SSH banner grab"""
        banner = self._raw_connect(ip, port)
        # SSH banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        version = ""
        match = re.search(r"SSH-\S+", banner)
        if match:
            version = match.group(0)
        return banner[:200], version

    def _grab_telnet(self, ip: str, port: int) -> Tuple[str, str]:
        """Telnet banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            # Telnet sends control sequences — read raw bytes
            data = sock.recv(256)
            sock.close()
            # Filter printable characters
            printable = re.sub(r'[^\x20-\x7e\r\n]', '', data.decode("utf-8", errors="ignore"))
            return printable[:200], "Telnet Service"
        except Exception:
            return "", ""

    def _grab_smtp(self, ip: str, port: int) -> Tuple[str, str]:
        """SMTP banner"""
        banner = self._raw_connect(ip, port)
        # SMTP: "220 mail.example.com ESMTP Postfix"
        match = re.search(r"220 (.+)", banner)
        version = match.group(1).strip() if match else ""
        return banner[:200], version

    def _grab_http(self, ip: str, port: int) -> Tuple[str, str]:
        """HTTP banner via HEAD request"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
            sock.send(request.encode())
            response = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()

            # Extract Server header
            server = ""
            match = re.search(r"Server:\s*(.+)", response, re.IGNORECASE)
            if match:
                server = match.group(1).strip()

            # Extract status line
            status = response.split("\r\n")[0] if response else ""

            version = f"{server} [{status}]" if server else status
            return response[:400], version
        except Exception:
            return "", ""

    def _grab_https(self, ip: str, port: int) -> Tuple[str, str]:
        """HTTPS banner (SSL/TLS)"""
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            ssock = ctx.wrap_socket(sock, server_hostname=ip)

            # Get certificate info
            cert = ssock.getpeercert()
            cn = ""
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                cn = subject.get("commonName", "")

            # Send HTTP request
            request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
            ssock.send(request.encode())
            response = ssock.recv(1024).decode("utf-8", errors="ignore")
            ssock.close()

            server = ""
            match = re.search(r"Server:\s*(.+)", response, re.IGNORECASE)
            if match:
                server = match.group(1).strip()

            version = f"HTTPS/{server}" + (f" CN={cn}" if cn else "")
            return response[:400], version
        except Exception:
            return "", ""

    def _grab_smb(self, ip: str, port: int) -> Tuple[str, str]:
        """SMB detection — just confirm it's SMB"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # SMB negotiate protocol request (raw bytes)
            negotiate = (
                b"\x00\x00\x00\x85"  # NetBIOS header
                b"\xff\x53\x4d\x42"  # SMB magic
                b"\x72\x00\x00\x00"  # Negotiate protocol
                b"\x00\x18\x53\xc8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\xff\xfe"
                b"\x00\x00\x00\x00"
            )
            sock.send(negotiate)
            response = sock.recv(256)
            sock.close()

            if len(response) > 4 and b"\xff\x53\x4d\x42" in response:
                return "SMB/CIFS", "Windows SMB Service"
            return "SMB Port", "SMB/CIFS (unconfirmed)"
        except Exception:
            return "SMB Port", "SMB/CIFS"

    def _grab_mysql(self, ip: str, port: int) -> Tuple[str, str]:
        """MySQL banner"""
        try:
            banner = self._raw_connect(ip, port)
            # MySQL sends version in initial handshake
            # Look for version string
            match = re.search(r"\d+\.\d+\.\d+[\w.-]*", banner)
            version = f"MySQL {match.group(0)}" if match else "MySQL"
            return banner[:200], version
        except Exception:
            return "", "MySQL"

    def _grab_redis(self, ip: str, port: int) -> Tuple[str, str]:
        """Redis INFO command"""
        try:
            banner = self._raw_connect(ip, port, b"INFO server\r\n")
            match = re.search(r"redis_version:(.+)", banner)
            version = f"Redis {match.group(1).strip()}" if match else "Redis"
            return banner[:200], version
        except Exception:
            return "", "Redis"

    def _grab_pop3(self, ip: str, port: int) -> Tuple[str, str]:
        """POP3 banner"""
        banner = self._raw_connect(ip, port)
        match = re.search(r"\+OK (.+)", banner)
        version = match.group(1).strip() if match else "POP3"
        return banner[:200], version

    def _grab_imap(self, ip: str, port: int) -> Tuple[str, str]:
        """IMAP banner"""
        banner = self._raw_connect(ip, port)
        match = re.search(r"\* OK (.+)", banner)
        version = match.group(1).strip() if match else "IMAP"
        return banner[:200], version

    def _extract_version(self, banner: str) -> str:
        """Generic version extraction from banner"""
        # Look for version-like patterns: "X.Y.Z" or "vX.Y"
        match = re.search(r"v?\d+\.\d+[\.\d]*", banner)
        if match:
            return match.group(0)
        # Take first meaningful line
        lines = [l.strip() for l in banner.split("\n") if l.strip()]
        return lines[0][:80] if lines else ""


# ═══════════════════════════════════════════════════════════════
# PORT SCANNER
# ═══════════════════════════════════════════════════════════════

class PortScanner:
    """Multi-threaded port scanner with banner grabbing"""

    def __init__(self, timeout: float = 1.0, threads: int = 100,
                 banner_grab: bool = True, verbose: bool = False):
        self.timeout     = timeout
        self.threads     = threads
        self.banner_grab = banner_grab
        self.verbose     = verbose
        self.grabber     = BannerGrabber(timeout=timeout * 2)

    def scan_port(self, ip: str, port: int) -> Optional[ServiceInfo]:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:  # Port is open
                service = ServiceInfo(
                    port  = port,
                    state = "open",
                    name  = PORT_SERVICES.get(port, "unknown"),
                )

                # Grab banner if enabled
                if self.banner_grab:
                    banner, version = self.grabber.grab(ip, port)
                    service.banner  = banner[:100] if banner else ""
                    service.version = version[:100] if version else ""

                return service
        except Exception:
            pass
        return None

    def scan_host(self, ip: str, ports: List[int]) -> List[ServiceInfo]:
        """Scan all ports on a host"""
        open_services = []

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self.scan_port, ip, port): port for port in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_services.append(result)

        # Sort by port number
        return sorted(open_services, key=lambda s: s.port)


# ═══════════════════════════════════════════════════════════════
# NETWORK SCANNER
# ═══════════════════════════════════════════════════════════════

class NetworkScanner:
    """Main scanner — discovers hosts and scans ports"""

    def __init__(self, ports: List[int] = None, timeout: float = 1.0,
                 threads: int = 50, banner_grab: bool = True,
                 verbose: bool = False):
        self.ports        = ports or COMMON_PORTS
        self.timeout      = timeout
        self.threads      = threads
        self.banner_grab  = banner_grab
        self.verbose      = verbose
        self.fingerprinter = OSFingerprinter()
        self.port_scanner  = PortScanner(timeout, min(threads, 200), banner_grab, verbose)
        self.results:      List[HostInfo] = []
        self.lock          = threading.Lock()

    def scan_network(self, target: str) -> List[HostInfo]:
        """Scan a network range or single host"""
        hosts = self._parse_target(target)
        total = len(hosts)

        print(f"{Fore.CYAN}[*] Scanning {total} host(s) on {len(self.ports)} ports{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Banner grabbing: {'ON' if self.banner_grab else 'OFF'}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Started: {datetime.now().strftime('%H:%M:%S')}{Style.RESET_ALL}\n")

        self.results = []
        done = 0

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._scan_single_host, str(ip)): str(ip)
                      for ip in hosts}
            for future in as_completed(futures):
                done += 1
                result = future.result()
                if result and result.is_up:
                    with self.lock:
                        self.results.append(result)
                        self._print_host(result)

                # Progress
                pct = int((done / total) * 30)
                bar = "█" * pct + "░" * (30 - pct)
                print(f"\r  [{bar}] {done}/{total}", end="", flush=True)

        print(f"\r  [{'█'*30}] {total}/{total}\n")
        return sorted(self.results, key=lambda h: socket.inet_aton(h.ip))

    def _parse_target(self, target: str) -> List[ipaddress.IPv4Address]:
        """Parse target string into list of IP addresses"""
        try:
            # CIDR notation: 192.168.1.0/24
            network = ipaddress.IPv4Network(target, strict=False)
            hosts   = list(network.hosts())
            # For /32 (single host), include that IP
            if network.prefixlen == 32:
                hosts = [network.network_address]
            return hosts
        except ValueError:
            try:
                # Single IP
                return [ipaddress.IPv4Address(target)]
            except ValueError:
                # Hostname
                try:
                    ip = socket.gethostbyname(target)
                    return [ipaddress.IPv4Address(ip)]
                except socket.gaierror:
                    print(f"{Fore.RED}[!] Cannot resolve: {target}{Style.RESET_ALL}")
                    sys.exit(1)

    def _scan_single_host(self, ip: str) -> Optional[HostInfo]:
        """Full scan of a single host"""
        host = HostInfo(ip=ip)

        # Step 1: Ping to check if up + get TTL for OS fingerprint
        is_up, ttl = self.fingerprinter.ping_host(ip, timeout=1)

        # Step 2: If ping fails, try TCP connect on common ports
        if not is_up:
            for port in [80, 443, 22, 445]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    if sock.connect_ex((ip, port)) == 0:
                        is_up = True
                        sock.close()
                        break
                    sock.close()
                except Exception:
                    pass

        if not is_up:
            return None

        host.is_up    = True
        host.ttl      = ttl
        host.os_guess = self.fingerprinter.guess_os_from_ttl(ttl) if ttl > 0 else "Unknown"

        # Step 3: Hostname lookup
        try:
            host.hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            host.hostname = ""

        # Step 4: Port scan + banner grab
        host.open_ports = self.port_scanner.scan_host(ip, self.ports)

        return host

    def _print_host(self, host: HostInfo):
        """Print host results to console"""
        hostname_str = f" ({host.hostname})" if host.hostname else ""
        os_str       = f" [{host.os_guess}]" if host.os_guess != "Unknown" else ""
        ttl_str      = f" TTL={host.ttl}" if host.ttl else ""

        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}HOST: {host.ip}{hostname_str}{Style.RESET_ALL}")
        print(f"  OS Guess  : {Fore.YELLOW}{host.os_guess}{Style.RESET_ALL}{ttl_str}")

        if not host.open_ports:
            print(f"  {Fore.YELLOW}No open ports found{Style.RESET_ALL}")
            return

        print(f"  Open Ports: {len(host.open_ports)}\n")
        print(f"  {Fore.CYAN}{'PORT':<8} {'STATE':<8} {'SERVICE':<12} {'VERSION/BANNER'}{Style.RESET_ALL}")
        print(f"  {'─'*56}")

        for svc in host.open_ports:
            port_str    = f"{svc.port}/tcp"
            state_color = Fore.GREEN if svc.state == "open" else Fore.RED
            version_str = svc.version or svc.banner[:50] or ""

            # Highlight dangerous services
            danger = ""
            if svc.port in [23, 21] or "ANONYMOUS" in version_str.upper():
                danger = f" {Fore.RED}⚠️ DANGEROUS{Style.RESET_ALL}"

            print(f"  {state_color}{port_str:<8}{Style.RESET_ALL} "
                  f"{svc.state:<8} "
                  f"{svc.name:<12} "
                  f"{version_str[:40]}{danger}")

    def print_summary(self):
        """Print final scan summary"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{'='*60}")
        print(f"  Hosts up      : {len(self.results)}")
        total_ports = sum(len(h.open_ports) for h in self.results)
        print(f"  Open ports    : {total_ports}")
        print(f"  Scan completed: {datetime.now().strftime('%H:%M:%S')}")

        # OS distribution
        if self.results:
            print(f"\n  {Fore.CYAN}OS Distribution:{Style.RESET_ALL}")
            os_counts: Dict[str, int] = {}
            for h in self.results:
                os_counts[h.os_guess] = os_counts.get(h.os_guess, 0) + 1
            for os_name, count in sorted(os_counts.items(), key=lambda x: -x[1]):
                print(f"    {count}x {os_name}")

        # Interesting findings
        interesting = []
        for h in self.results:
            for svc in h.open_ports:
                if svc.port == 23:
                    interesting.append(f"{h.ip}:{svc.port} — Telnet open!")
                if svc.port == 21 and "ANONYMOUS" in svc.version.upper():
                    interesting.append(f"{h.ip}:{svc.port} — FTP Anonymous login!")
                if svc.port in [6379, 27017]:
                    interesting.append(f"{h.ip}:{svc.port} — {svc.name} potentially unauthenticated!")

        if interesting:
            print(f"\n  {Fore.RED}⚠️  Interesting Findings:{Style.RESET_ALL}")
            for finding in interesting:
                print(f"    {Fore.RED}→ {finding}{Style.RESET_ALL}")

        print(f"{'='*60}\n")

    def save_json(self, filepath: str):
        """Save results to JSON file"""
        data = {
            "scan_time" : datetime.now().isoformat(),
            "scanner"   : f"Local Network Scanner v{VERSION}",
            "author"    : "PasinduSD",
            "hosts"     : [
                {
                    "ip"        : h.ip,
                    "hostname"  : h.hostname,
                    "is_up"     : h.is_up,
                    "ttl"       : h.ttl,
                    "os_guess"  : h.os_guess,
                    "open_ports": [
                        {
                            "port"   : s.port,
                            "state"  : s.state,
                            "name"   : s.name,
                            "version": s.version,
                            "banner" : s.banner[:100],
                        }
                        for s in h.open_ports
                    ],
                }
                for h in self.results
            ],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"{Fore.GREEN}[+] Results saved: {filepath}{Style.RESET_ALL}")


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════

def parse_ports(port_str: str) -> List[int]:
    """Parse port string: '22,80,443' or '1-1024' or '80'"""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description=f"Local Network Scanner v{VERSION} — by PasinduSD",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan single host (full)
  python local_network_scanner.py -t 192.168.1.1

  # Scan network range
  python local_network_scanner.py -t 192.168.1.0/24

  # Fast scan (9 common ports)
  python local_network_scanner.py -t 192.168.1.0/24 --fast

  # Custom ports
  python local_network_scanner.py -t 192.168.1.1 -p 22,80,443,8080,3000

  # Port range
  python local_network_scanner.py -t 192.168.1.1 -p 1-1000

  # No banner grabbing (faster)
  python local_network_scanner.py -t 192.168.1.0/24 --no-banner

  # Save to JSON
  python local_network_scanner.py -t 192.168.1.0/24 --json scan_results.json

  # Verbose
  python local_network_scanner.py -t 192.168.1.1 -v
        """
    )

    parser.add_argument("-t", "--target",    required=True,
                        help="Target IP, hostname, or CIDR range (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports",     default="",
                        help="Ports to scan: '22,80,443' or '1-1024' (default: common ports)")
    parser.add_argument("--fast",            action="store_true",
                        help="Fast scan: only 9 most common ports")
    parser.add_argument("--no-banner",       action="store_true",
                        help="Skip banner grabbing (faster scan)")
    parser.add_argument("--timeout",         type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("--threads",         type=int,   default=100,
                        help="Number of threads (default: 100)")
    parser.add_argument("--json",            default="",
                        help="Save results to JSON file")
    parser.add_argument("-v", "--verbose",   action="store_true",
                        help="Verbose output")
    args = parser.parse_args()

    # Determine ports
    if args.ports:
        try:
            ports = parse_ports(args.ports)
        except ValueError as e:
            print(f"{Fore.RED}[!] Invalid port format: {e}{Style.RESET_ALL}")
            sys.exit(1)
    elif args.fast:
        ports = FAST_PORTS
        print(f"{Fore.CYAN}[*] Fast mode: {ports}{Style.RESET_ALL}")
    else:
        ports = COMMON_PORTS

    # Run scanner
    scanner = NetworkScanner(
        ports       = ports,
        timeout     = args.timeout,
        threads     = args.threads,
        banner_grab = not args.no_banner,
        verbose     = args.verbose,
    )

    try:
        scanner.scan_network(args.target)
        scanner.print_summary()

        if args.json:
            scanner.save_json(args.json)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted.{Style.RESET_ALL}")
        scanner.print_summary()


if __name__ == "__main__":
    main()