"""
Modul 1: Učitavanje i parsiranje mrežnog saobraćaja iz .pcap fajlova
"""

from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from datetime import datetime


class PcapLoader:
    """Klasa za učitavanje i osnovno parsiranje PCAP fajlova"""
    
    def __init__(self):
        self.packets = []
        self.file_path = None
        
    def load_pcap(self, file_path):
        """
        Učitava PCAP fajl
        
        Args:
            file_path (str): Putanja do .pcap fajla
            
        Returns:
            int: Broj učitanih paketa
        """
        try:
            print(f"[PCAP Loader] Učitavanje fajla: {file_path}")
            self.file_path = file_path
            self.packets = rdpcap(file_path)
            print(f"[PCAP Loader] Uspešno učitano {len(self.packets)} paketa")
            return len(self.packets)
        except Exception as e:
            print(f"[PCAP Loader] Greška pri učitavanju: {e}")
            return 0
    
    def parse_packet(self, packet):
        """
        Parsira pojedinačni paket i izvlači osnovne informacije
        
        Args:
            packet: Scapy paket objekat
            
        Returns:
            dict: Osnovne informacije o paketu
        """
        packet_info = {
            'timestamp': float(packet.time),
            'datetime': datetime.fromtimestamp(float(packet.time)),
            'length': len(packet),
            'has_ip': IP in packet,
            'raw_packet': packet
        }
        
        if IP in packet:
            packet_info.update({
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': self._get_protocol(packet)
            })
            
            if TCP in packet:
                packet_info.update({
                    'src_port': packet[TCP].sport,
                    'dst_port': packet[TCP].dport,
                    'tcp_flags': str(packet[TCP].flags)
                })
            elif UDP in packet:
                packet_info.update({
                    'src_port': packet[UDP].sport,
                    'dst_port': packet[UDP].dport
                })
        
        return packet_info
    
    def _get_protocol(self, packet):
        """Određuje protokol paketa"""
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        elif ICMP in packet:
            return 'ICMP'
        else:
            return 'OTHER'
    
    def get_all_packets(self):
        """Vraća sve učitane pakete"""
        return self.packets
    
    def get_packet_count(self):
        """Vraća broj učitanih paketa"""
        return len(self.packets)


if __name__ == "__main__":
    # Test
    loader = PcapLoader()
    count = loader.load_pcap("sample.pcap")
    
    if count > 0:
        print(f"\nParsiranje prvog paketa:")
        first_packet = loader.get_all_packets()[0]
        parsed = loader.parse_packet(first_packet)
        print(parsed)