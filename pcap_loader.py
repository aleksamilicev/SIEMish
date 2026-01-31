"""
Modul 1: Učitavanje i parsiranje mrežnog saobraćaja iz .pcap fajlova
Optimizovana verzija sa batch processing-om
"""

from scapy.all import PcapReader, IP, TCP, UDP, ICMP
from datetime import datetime


class PcapLoader:
    """Klasa za učitavanje i osnovno parsiranje PCAP fajlova"""
    
    def __init__(self):
        self.file_path = None
        self.total_packets = 0
        self.batch_size = 10000  # Procesiramo po 10k paketa
        
    def load_pcap(self, file_path):
        """
        Broji pakete u PCAP fajlu bez učitavanja u memoriju
        
        Args:
            file_path (str): Putanja do .pcap fajla
            
        Returns:
            int: Broj paketa u fajlu
        """
        try:
            print(f"[PCAP Loader] Prebrojavanje paketa u fajlu: {file_path}")
            self.file_path = file_path
            self.total_packets = 0
            
            # Brzo prebrojavanje paketa
            with PcapReader(file_path) as pcap_reader:
                for _ in pcap_reader:
                    self.total_packets += 1
                    
                    # Feedback na svakih 100k paketa
                    if self.total_packets % 100000 == 0:
                        print(f"[PCAP Loader] Prebrojano {self.total_packets} paketa...")
            
            print(f"[PCAP Loader] Ukupno paketa: {self.total_packets}")
            return self.total_packets
            
        except Exception as e:
            print(f"[PCAP Loader] Greška pri učitavanju: {e}")
            return 0
    
    def parse_packets_batch(self, start=0, count=None, callback=None):
        """
        Parsira pakete u batch-evima (streaming pristup)
        
        Args:
            start (int): Indeks od kog počinje parsiranje
            count (int): Broj paketa za parsiranje (None = svi)
            callback (function): Funkcija koja se poziva nakon svakog batch-a
            
        Yields:
            dict: Parsirani paket
        """
        if not self.file_path:
            return
        
        try:
            with PcapReader(self.file_path) as pcap_reader:
                current_index = 0
                parsed_count = 0
                max_count = count if count else self.total_packets
                
                for packet in pcap_reader:
                    # Preskači pakete do start pozicije
                    if current_index < start:
                        current_index += 1
                        continue
                    
                    # Zaustavi se kad dostigneš limit
                    if parsed_count >= max_count:
                        break
                    
                    # Parsiraj paket
                    packet_info = self.parse_packet(packet, current_index)
                    if packet_info:
                        yield packet_info
                        parsed_count += 1
                    
                    current_index += 1
                    
                    # Callback za progress
                    if callback and parsed_count % 1000 == 0:
                        callback(parsed_count, max_count)
        
        except Exception as e:
            print(f"[PCAP Loader] Greška pri parsiranju: {e}")
    
    def parse_packet(self, packet, index):
        """
        Parsira pojedinačni paket i izvlači osnovne informacije
        
        Args:
            packet: Scapy paket objekat
            index (int): Indeks paketa
            
        Returns:
            dict: Osnovne informacije o paketu
        """
        packet_info = {
            'index': index,
            'timestamp': float(packet.time),
            'datetime': datetime.fromtimestamp(float(packet.time)),
            'length': len(packet),
            'has_ip': IP in packet,
            'raw_packet': None  # Ne čuvamo raw paket radi memorije
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
    
    def get_packet_count(self):
        """Vraća broj učitanih paketa"""
        return self.total_packets
    
    def parse_sample(self, sample_size=10000):
        """
        Parsira samo uzorak paketa za brzu analizu
        
        Args:
            sample_size (int): Broj paketa za uzorak
            
        Returns:
            list: Lista parsiranih paketa
        """
        print(f"[PCAP Loader] Parsiranje uzorka od {sample_size} paketa...")
        
        parsed = []
        for packet_info in self.parse_packets_batch(start=0, count=sample_size):
            parsed.append(packet_info)
        
        print(f"[PCAP Loader] Parsirano {len(parsed)} paketa")
        return parsed


if __name__ == "__main__":
    # Test
    loader = PcapLoader()
    count = loader.load_pcap("sample.pcap")
    
    if count > 0:
        print(f"\nParsiranje uzorka...")
        sample = loader.parse_sample(1000)
        print(f"Parsirano {len(sample)} paketa")
        
        if sample:
            print(f"\nPrimer prvog paketa:")
            print(sample[0])