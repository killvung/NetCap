import datetime
import logging
from dataclasses import dataclass
from scapy.all import sniff, Ether, IP, TCP, UDP

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

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
                flags=packet[IP].flags,
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
                flags=packet[TCP].flags,
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