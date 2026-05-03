"""
Trace Foundry - Port Scanner Module
Fast multi-threaded TCP port scanner with service detection
"""

import socket
import concurrent.futures
from utils.display import print_section, ok, warn, info

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP/TLS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2375: "Docker", 2376: "Docker TLS", 3000: "Node/Grafana",
    3306: "MySQL", 3389: "RDP", 4369: "RabbitMQ",
    5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC",
    6379: "Redis", 7001: "WebLogic", 8000: "HTTP-alt",
    8080: "HTTP-proxy", 8443: "HTTPS-alt", 8888: "Jupyter",
    9000: "PHP-FPM/Portainer", 9200: "Elasticsearch",
    9300: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 28017: "MongoDB HTTP"
}

class PortModule:
    def __init__(self, ip, custom_ports=None, threads=50, timeout=1):
        self.ip = ip
        self.ports = custom_ports if custom_ports else list(COMMON_PORTS.keys())
        self.threads = threads
        self.timeout = timeout

    def _scan(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.ip, port))
            sock.close()
            if result == 0:
                service = COMMON_PORTS.get(port, "unknown")
                # Try banner grabbing
                banner = self._grab_banner(port)
                return {"port": port, "service": service, "banner": banner, "state": "open"}
        except:
            pass
        return None

    def _grab_banner(self, port):
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((self.ip, port))
            if port in (80, 8080, 8000, 8888):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(256).decode("utf-8", errors="ignore").strip()
            s.close()
            return banner[:100] if banner else None
        except:
            return None

    def run(self):
        print_section("Port Scanning")
        info(f"Target IP   : {self.ip}")
        info(f"Ports       : {len(self.ports)} to scan")

        open_ports = []
        risky = {6379, 27017, 9200, 2375, 11211, 5432, 3306, 1433}

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._scan, p): p for p in self.ports}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    flag = "⚠️  EXPOSED DB/SERVICE!" if result["port"] in risky else ""
                    ok(f"Port {result['port']:5d}/tcp  {result['service']:20s} {flag}")
                    if result["banner"]:
                        info(f"  Banner: {result['banner'][:80]}")
                    open_ports.append(result)

        open_ports.sort(key=lambda x: x["port"])
        info(f"Open ports  : {len(open_ports)}")
        if not open_ports:
            warn("No open ports found")
        return open_ports
