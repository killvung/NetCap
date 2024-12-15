import datetime
import logging
from dataclasses import dataclass
from scapy.all import sniff, Ether, IP, TCP, UDP
import sqlite3

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Initialize SQLite database
conn = sqlite3.connect('packets.db')
cursor = conn.cursor()

# Create table for storing packets
cursor.execute('''
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    destination_mac TEXT,
    source_mac TEXT,
    ethertype INTEGER,
    version INTEGER,
    ihl INTEGER,
    dscp INTEGER,
    ecn INTEGER,
    total_length INTEGER,
    identification INTEGER,
    flags INTEGER,
    fragment_offset INTEGER,
    ttl INTEGER,
    protocol INTEGER,
    header_checksum INTEGER,
    source_ip TEXT,
    destination_ip TEXT,
    source_port INTEGER,
    destination_port INTEGER,
    sequence_number INTEGER,
    acknowledgment_number INTEGER,
    tcp_data_offset INTEGER,
    tcp_reserved INTEGER,
    tcp_flags INTEGER,
    window_size INTEGER,
    tcp_checksum INTEGER,
    urgent_pointer INTEGER,
    udp_length INTEGER,
    udp_checksum INTEGER,
    payload BLOB,
    timestamp TEXT
)
''')
conn.commit()

@dataclass
class EthernetFrame:
    destination_mac: str
    source_mac: str
    ethertype: int

    def __str__(self):
        return (f"Ethernet Frame:\n"
                f"  Destination MAC: {self.destination_mac}\n"
                f"  Source MAC: {self.source_mac}\n"
                f"  EtherType: {self.ethertype}")

@dataclass
class IPHeader:
    version: int
    ihl: int
    dscp: int
    ecn: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    header_checksum: int
    source_ip: str
    destination_ip: str

    def __str__(self):
        return (f"IP Header:\n"
                f"  Version: {self.version}\n"
                f"  IHL: {self.ihl}\n"
                f"  DSCP: {self.dscp}\n"
                f"  ECN: {self.ecn}\n"
                f"  Total Length: {self.total_length}\n"
                f"  Identification: {self.identification}\n"
                f"  Flags: {self.flags}\n"
                f"  Fragment Offset: {self.fragment_offset}\n"
                f"  TTL: {self.ttl}\n"
                f"  Protocol: {self.protocol}\n"
                f"  Header Checksum: {self.header_checksum}\n"
                f"  Source IP: {self.source_ip}\n"
                f"  Destination IP: {self.destination_ip}")

@dataclass
class TCPHeader:
    source_port: int
    destination_port: int
    sequence_number: int
    acknowledgment_number: int
    data_offset: int
    reserved: int
    flags: int
    window_size: int
    checksum: int
    urgent_pointer: int

    def __str__(self):
        return (f"TCP Header:\n"
                f"  Source Port: {self.source_port}\n"
                f"  Destination Port: {self.destination_port}\n"
                f"  Sequence Number: {self.sequence_number}\n"
                f"  Acknowledgment Number: {self.acknowledgment_number}\n"
                f"  Data Offset: {self.data_offset}\n"
                f"  Reserved: {self.reserved}\n"
                f"  Flags: {self.flags}\n"
                f"  Window Size: {self.window_size}\n"
                f"  Checksum: {self.checksum}\n"
                f"  Urgent Pointer: {self.urgent_pointer}")

@dataclass
class UDPHeader:
    source_port: int
    destination_port: int
    length: int
    checksum: int

    def __str__(self):
        return (f"UDP Header:\n"
                f"  Source Port: {self.source_port}\n"
                f"  Destination Port: {self.destination_port}\n"
                f"  Length: {self.length}\n"
                f"  Checksum: {self.checksum}")

@dataclass
class Packet:
    ethernet_frame: EthernetFrame
    ip_header: IPHeader
    transport_header: object
    payload: bytes
    timestamp: datetime.datetime = datetime.datetime.now()

    def __str__(self):
        return (f"Packet:\n"
                f"  {self.ethernet_frame}\n"
                f"  {self.ip_header}\n"
                f"  {self.transport_header}\n"
                f"  Payload: {self.payload}\n"
                f"  Timestamp: {self.timestamp}")

def packet_callback(packet):
    try:
        if Ether in packet:
            eth_frame = EthernetFrame(
                destination_mac=packet[Ether].dst,
                source_mac=packet[Ether].src,
                ethertype=packet[Ether].type
            )
        else:
            logger.warning("No Ethernet frame found in packet.")
            return

        if IP in packet:
            ip_header = IPHeader(
                version=packet[IP].version,
                ihl=packet[IP].ihl,
                dscp=packet[IP].tos >> 2,
                ecn=packet[IP].tos & 0x03,
                total_length=packet[IP].len,
                identification=packet[IP].id,
                flags=int(packet[IP].flags),
                fragment_offset=packet[IP].frag,
                ttl=packet[IP].ttl,
                protocol=packet[IP].proto,
                header_checksum=packet[IP].chksum,
                source_ip=packet[IP].src,
                destination_ip=packet[IP].dst
            )
        else:
            logger.warning("No IP header found in packet.")
            return

        transport_header = None
        if TCP in packet:
            transport_header = TCPHeader(
                source_port=packet[TCP].sport,
                destination_port=packet[TCP].dport,
                sequence_number=packet[TCP].seq,
                acknowledgment_number=packet[TCP].ack,
                data_offset=packet[TCP].dataofs,
                reserved=packet[TCP].reserved,
                flags=int(packet[TCP].flags),
                window_size=packet[TCP].window,
                checksum=packet[TCP].chksum,
                urgent_pointer=packet[TCP].urgptr
            )
        elif UDP in packet:
            transport_header = UDPHeader(
                source_port=packet[UDP].sport,
                destination_port=packet[UDP].dport,
                length=packet[UDP].len,
                checksum=packet[UDP].chksum
            )
        else:
            logger.warning("No TCP or UDP header found in packet.")
            return

        payload = bytes(packet[IP].payload)

        captured_packet = Packet(eth_frame, ip_header, transport_header, payload)
        logger.info(f"Captured packet:\n{captured_packet}")

        # Insert packet data into SQLite database
        cursor.execute('''
        INSERT INTO packets (
            destination_mac, source_mac, ethertype, version, ihl, dscp, ecn, total_length,
            identification, flags, fragment_offset, ttl, protocol, header_checksum, source_ip,
            destination_ip, source_port, destination_port, sequence_number, acknowledgment_number,
            tcp_data_offset, tcp_reserved, tcp_flags, window_size, tcp_checksum, urgent_pointer,
            udp_length, udp_checksum, payload, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            eth_frame.destination_mac, eth_frame.source_mac, eth_frame.ethertype,
            ip_header.version, ip_header.ihl, ip_header.dscp, ip_header.ecn, ip_header.total_length,
            ip_header.identification, ip_header.flags, ip_header.fragment_offset, ip_header.ttl,
            ip_header.protocol, ip_header.header_checksum, ip_header.source_ip, ip_header.destination_ip,
            transport_header.source_port if transport_header else None,
            transport_header.destination_port if transport_header else None,
            transport_header.sequence_number if isinstance(transport_header, TCPHeader) else None,
            transport_header.acknowledgment_number if isinstance(transport_header, TCPHeader) else None,
            transport_header.data_offset if isinstance(transport_header, TCPHeader) else None,
            transport_header.reserved if isinstance(transport_header, TCPHeader) else None,
            transport_header.flags if isinstance(transport_header, TCPHeader) else None,
            transport_header.window_size if isinstance(transport_header, TCPHeader) else None,
            transport_header.checksum if isinstance(transport_header, TCPHeader) else None,
            transport_header.urgent_pointer if isinstance(transport_header, TCPHeader) else None,
            transport_header.length if isinstance(transport_header, UDPHeader) else None,
            transport_header.checksum if isinstance(transport_header, UDPHeader) else None,
            payload,  # This corresponds to the `payload` column
            captured_packet.timestamp.isoformat()  # This corresponds to the `timestamp` column
        ))
        conn.commit()
    except Exception as e:
        logger.error(f"Error processing packet: {e}")

def main():
    try:
        logger.info("Starting packet capture...")
        sniff(prn=packet_callback, store=0)
    except Exception as e:
        logger.error(f"Error during packet capture: {e}")

if __name__ == "__main__":
    main()