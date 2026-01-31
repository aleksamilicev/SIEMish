"""
Modul 2: Ekstrakcija i normalizacija relevantnih log događaja
"""

from datetime import datetime


class LogExtractor:
    """Klasa za ekstrakciju i normalizaciju log događaja iz parsiranih paketa"""
    
    def __init__(self):
        self.log_events = []
        
    def extract_events(self, parsed_packets):
        """
        Ekstraktuje log događaje iz parsiranih paketa
        
        Args:
            parsed_packets (list): Lista parsiranih paketa
            
        Returns:
            list: Lista normalizovanih log događaja
        """
        print(f"[Log Extractor] Ekstrakcija događaja iz {len(parsed_packets)} paketa...")
        
        self.log_events = []
        for packet in parsed_packets:
            event = self._normalize_packet_to_event(packet)
            if event:
                self.log_events.append(event)
        
        print(f"[Log Extractor] Ekstrahovano {len(self.log_events)} log događaja")
        return self.log_events
    
    def _normalize_packet_to_event(self, packet):
        """
        Normalizuje paket u standardizovani log događaj
        
        Args:
            packet (dict): Parsiran paket
            
        Returns:
            dict: Normalizovani log događaj
        """
        if not packet.get('has_ip'):
            return None
        
        event = {
            'timestamp': packet['datetime'].isoformat(),
            'event_type': self._determine_event_type(packet),
            'src_ip': packet.get('src_ip'),
            'dst_ip': packet.get('dst_ip'),
            'src_port': packet.get('src_port'),
            'dst_port': packet.get('dst_port'),
            'protocol': packet.get('protocol'),
            'length': packet.get('length'),
            'severity': 'INFO'
        }
        
        return event
    
    def _determine_event_type(self, packet):
        """
        Određuje tip događaja na osnovu porta i protokola
        
        Args:
            packet (dict): Parsiran paket
            
        Returns:
            str: Tip događaja
        """
        dst_port = packet.get('dst_port')
        protocol = packet.get('protocol')
        
        # Mapiranje portova na tipove događaja
        port_mapping = {
            22: 'SSH_CONNECTION',
            23: 'TELNET_CONNECTION',
            21: 'FTP_CONNECTION',
            80: 'HTTP_REQUEST',
            443: 'HTTPS_REQUEST',
            3389: 'RDP_CONNECTION',
            3306: 'MYSQL_CONNECTION',
            5432: 'POSTGRES_CONNECTION',
            1433: 'MSSQL_CONNECTION'
        }
        
        if dst_port in port_mapping:
            return port_mapping[dst_port]
        
        if protocol == 'ICMP':
            return 'ICMP_PACKET'
        
        return 'NETWORK_TRAFFIC'
    
    def get_events(self):
        """Vraća sve ekstrahovane događaje"""
        return self.log_events
    
    def get_events_by_type(self, event_type):
        """Filtrira događaje po tipu"""
        return [e for e in self.log_events if e['event_type'] == event_type]
    
    def get_events_by_ip(self, ip_address):
        """Filtrira događaje po IP adresi (izvorna ili odredišna)"""
        return [e for e in self.log_events 
                if e['src_ip'] == ip_address or e['dst_ip'] == ip_address]


if __name__ == "__main__":
    # Test sa dummy podacima
    from pcap_loader import PcapLoader
    
    loader = PcapLoader()
    count = loader.load_pcap("sample.pcap")
    
    if count > 0:
        # Parsiranje paketa
        parsed = [loader.parse_packet(p) for p in loader.get_all_packets()[:100]]
        
        # Ekstrakcija događaja
        extractor = LogExtractor()
        events = extractor.extract_events(parsed)
        
        print(f"\nPrvih 5 događaja:")
        for event in events[:5]:
            print(event)