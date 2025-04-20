from scapy.all import TCP, UDP, IP, sr1
from abc import abstractmethod
import sys

tcp_port_service_mapping = {
    80: "HTTP",
    443: "HTTPS",
    21: "FTP",
    22: "SFTP",
    22: "SSH",
    25: "SMTP",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    3389: "RDP",
    389: "LDAP",
    88: "Kerberos",
    5900: "VNC",
    445: "SMB",
    179: "BGP",
}

udp_port_service_mapping = {
    53: "DNS",
    161: "SNMP",
    123: "NTP",
    67: "DHCP",
    179: "BGP (UDP)",
    123: "NTP (UDP)"
}

class AbstractScanner(object):
    @abstractmethod
    def scan(self, ip_address, port):
        pass

class TCPScanner(AbstractScanner):
    def scan(self, ip_address, port):
        packet = IP(dst=ip_address)/TCP(sport=port, dport=port, flags="S")
        response = sr1(packet)

        flags = response.getlayer(TCP).flags
        syn_ack = (flags & 0x02) and (flags & 0x10) # Because the connection can be reset (FIN/RST)

        if response and response.haslayer(TCP) and syn_ack:
            print(f"""
                Port {port} on {ip_address} is open (TCP handshake successful).
                Service {tcp_port_service_mapping.get(port)} is running on port {port}.
            """)
        else:
            print(f"No service on {ip_address}:{port} is open or connection is reset")


class UDPScanner(AbstractScanner):
    def scan(self, ip_address, port):
        packet = IP(dst=ip_address)/UDP(sport=port, dport=port)
        response = sr1(packet)

        if response and response.haslayer(UDP):
            print(f"""
                Port {port} on {ip_address} is open.
                Service {udp_port_service_mapping.get(port)} is running on port {port}.
            """)
        else:
            print(f"No service on {ip_address}:{port} is open or unreachable")

tcp_scanner = TCPScanner()
udp_scanner = UDPScanner()

def scan():
    if len(sys.argv) >= 3:
        type = str(sys.argv[1])
        ip_address = str(sys.argv[2])
        port = int(sys.argv[3])

        if type == "udp":
            udp_scanner.scan(ip_address, port)
        else:
            tcp_scanner.scan(ip_address, port)

scan()

