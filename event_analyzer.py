"""
Modul 3: Agregacija i analiza frekventnosti događaja
"""

from collections import defaultdict, Counter
from datetime import datetime


class EventAnalyzer:
    """Klasa za agregaciju i analizu frekventnosti log događaja"""
    
    def __init__(self):
        self.events = []
        self.analysis_results = {}
        
    def analyze_events(self, log_events):
        """
        Analizira log događaje i računa frekventnosti
        
        Args:
            log_events (list): Lista log događaja
            
        Returns:
            dict: Rezultati analize
        """
        print(f"[Event Analyzer] Analiza {len(log_events)} događaja...")
        
        self.events = log_events
        
        self.analysis_results = {
            'ip_frequency': self._analyze_ip_frequency(),
            'port_frequency': self._analyze_port_frequency(),
            'event_type_frequency': self._analyze_event_type_frequency(),
            'protocol_distribution': self._analyze_protocol_distribution(),
            'time_distribution': self._analyze_time_distribution()
        }
        
        print(f"[Event Analyzer] Analiza završena")
        return self.analysis_results
    
    def _analyze_ip_frequency(self):
        """Analizira frekventnost IP adresa"""
        src_ip_counter = Counter()
        dst_ip_counter = Counter()
        
        for event in self.events:
            if event.get('src_ip'):
                src_ip_counter[event['src_ip']] += 1
            if event.get('dst_ip'):
                dst_ip_counter[event['dst_ip']] += 1
        
        return {
            'source_ips': dict(src_ip_counter.most_common(20)),
            'destination_ips': dict(dst_ip_counter.most_common(20)),
            'top_source': src_ip_counter.most_common(1)[0] if src_ip_counter else None,
            'top_destination': dst_ip_counter.most_common(1)[0] if dst_ip_counter else None
        }
    
    def _analyze_port_frequency(self):
        """Analizira frekventnost portova"""
        src_port_counter = Counter()
        dst_port_counter = Counter()
        
        for event in self.events:
            if event.get('src_port'):
                src_port_counter[event['src_port']] += 1
            if event.get('dst_port'):
                dst_port_counter[event['dst_port']] += 1
        
        return {
            'source_ports': dict(src_port_counter.most_common(20)),
            'destination_ports': dict(dst_port_counter.most_common(20))
        }
    
    def _analyze_event_type_frequency(self):
        """Analizira frekventnost tipova događaja"""
        event_type_counter = Counter()
        
        for event in self.events:
            event_type_counter[event['event_type']] += 1
        
        return dict(event_type_counter.most_common())
    
    def _analyze_protocol_distribution(self):
        """Analizira distribuciju protokola"""
        protocol_counter = Counter()
        
        for event in self.events:
            if event.get('protocol'):
                protocol_counter[event['protocol']] += 1
        
        return dict(protocol_counter)
    
    def _analyze_time_distribution(self):
        """Analizira distribuciju događaja kroz vreme"""
        time_buckets = defaultdict(int)
        
        for event in self.events:
            timestamp = datetime.fromisoformat(event['timestamp'])
            # Grupiranje po minutima
            time_key = timestamp.strftime('%Y-%m-%d %H:%M')
            time_buckets[time_key] += 1
        
        return dict(sorted(time_buckets.items()))
    
    def get_suspicious_ips(self, threshold=50):
        """
        Identifikuje sumnjive IP adrese (više od threshold paketa)
        
        Args:
            threshold (int): Prag za broj paketa
            
        Returns:
            list: Lista sumnjivih IP adresa
        """
        suspicious = []
        
        if 'ip_frequency' in self.analysis_results:
            for ip, count in self.analysis_results['ip_frequency']['source_ips'].items():
                if count > threshold:
                    suspicious.append({
                        'ip': ip,
                        'count': count,
                        'type': 'source'
                    })
        
        return suspicious
    
    def get_results(self):
        """Vraća sve rezultate analize"""
        return self.analysis_results
    
    def print_summary(self):
        """Ispisuje sažetak analize"""
        if not self.analysis_results:
            print("Nema rezultata analize")
            return
        
        print("\n" + "="*60)
        print("SAŽETAK ANALIZE")
        print("="*60)
        
        print(f"\nUkupno analiziranih događaja: {len(self.events)}")
        
        print("\nTop 5 izvornih IP adresa:")
        for ip, count in list(self.analysis_results['ip_frequency']['source_ips'].items())[:5]:
            print(f"  {ip}: {count} paketa")
        
        print("\nDistribucija protokola:")
        for protocol, count in self.analysis_results['protocol_distribution'].items():
            print(f"  {protocol}: {count} paketa")
        
        print("\nTop 5 tipova događaja:")
        for event_type, count in list(self.analysis_results['event_type_frequency'].items())[:5]:
            print(f"  {event_type}: {count}")


if __name__ == "__main__":
    # Test
    from pcap_loader import PcapLoader
    from log_extractor import LogExtractor
    
    loader = PcapLoader()
    count = loader.load_pcap("sample.pcap")
    
    if count > 0:
        parsed = [loader.parse_packet(p) for p in loader.get_all_packets()[:1000]]
        
        extractor = LogExtractor()
        events = extractor.extract_events(parsed)
        
        analyzer = EventAnalyzer()
        results = analyzer.analyze_events(events)
        analyzer.print_summary()