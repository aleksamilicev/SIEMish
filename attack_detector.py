"""
Modul 4: Detekcija napada na osnovu unapred definisanih pravila
"""

from collections import defaultdict
from datetime import datetime


class AttackDetector:
    """Klasa za detekciju mrežnih napada na osnovu definisanih pravila"""
    
    def __init__(self):
        self.events = []
        self.analysis_results = {}
        self.detected_attacks = []
        
        # Pragovi za detekciju
        self.thresholds = {
            'bruteforce_threshold': 50,      # Broj pokušaja za bruteforce
            'port_scan_threshold': 5,         # Broj različitih portova
            'dos_threshold': 100,             # Broj paketa za DoS
            'connection_threshold': 20        # Broj konekcija u kratkom vremenu
        }
    
    def detect_attacks(self, log_events, analysis_results):
        """
        Detektuje napade primenom definisanih pravila
        
        Args:
            log_events (list): Lista log događaja
            analysis_results (dict): Rezultati analize frekventnosti
            
        Returns:
            list: Lista detektovanih napada
        """
        print(f"[Attack Detector] Detekcija napada na {len(log_events)} događaja...")
        
        self.events = log_events
        self.analysis_results = analysis_results
        self.detected_attacks = []
        
        # Primena različitih pravila detekcije
        self._detect_bruteforce()
        self._detect_port_scanning()
        self._detect_dos()
        self._detect_suspicious_connections()
        
        print(f"[Attack Detector] Detektovano {len(self.detected_attacks)} napada")
        return self.detected_attacks
    
    def _detect_bruteforce(self):
        """
        Pravilo 1: Detekcija bruteforce napada
        Detektuje visok broj pokušaja konekcije sa iste IP adrese
        """
        if 'ip_frequency' not in self.analysis_results:
            return
        
        source_ips = self.analysis_results['ip_frequency']['source_ips']
        
        for ip, count in source_ips.items():
            if count > self.thresholds['bruteforce_threshold']:
                # Provera da li su ciljani autentifikacioni portovi
                auth_ports = [22, 23, 21, 3389]  # SSH, Telnet, FTP, RDP
                events_from_ip = [e for e in self.events if e['src_ip'] == ip]
                
                auth_attempts = sum(1 for e in events_from_ip 
                                   if e.get('dst_port') in auth_ports)
                
                if auth_attempts > 20:  # Više od 20 pokušaja na auth portove
                    self.detected_attacks.append({
                        'type': 'BRUTEFORCE',
                        'severity': 'HIGH',
                        'source_ip': ip,
                        'target_ports': list(set(e.get('dst_port') for e in events_from_ip 
                                                if e.get('dst_port') in auth_ports)),
                        'attempt_count': auth_attempts,
                        'total_packets': count,
                        'description': f'Detektovan bruteforce napad sa {ip}: {auth_attempts} pokušaja autentifikacije',
                        'timestamp': datetime.now().isoformat()
                    })
    
    def _detect_port_scanning(self):
        """
        Pravilo 2: Detekcija port scanning napada
        Detektuje pokušaje skeniranja većeg broja portova
        """
        ip_port_map = defaultdict(set)
        
        for event in self.events:
            src_ip = event.get('src_ip')
            dst_port = event.get('dst_port')
            
            if src_ip and dst_port:
                ip_port_map[src_ip].add(dst_port)
        
        for ip, ports in ip_port_map.items():
            if len(ports) > self.thresholds['port_scan_threshold']:
                self.detected_attacks.append({
                    'type': 'PORT_SCAN',
                    'severity': 'MEDIUM',
                    'source_ip': ip,
                    'scanned_ports': list(ports),
                    'port_count': len(ports),
                    'description': f'Detektovan port scanning sa {ip}: {len(ports)} različitih portova',
                    'timestamp': datetime.now().isoformat()
                })
    
    def _detect_dos(self):
        """
        Pravilo 3: Detekcija DoS/DDoS napada
        Detektuje abnormalno visok broj paketa sa jedne IP adrese
        """
        if 'ip_frequency' not in self.analysis_results:
            return
        
        source_ips = self.analysis_results['ip_frequency']['source_ips']
        
        for ip, count in source_ips.items():
            if count > self.thresholds['dos_threshold']:
                events_from_ip = [e for e in self.events if e['src_ip'] == ip]
                
                # Analiza ciljanih destinacija
                target_ips = [e['dst_ip'] for e in events_from_ip if e.get('dst_ip')]
                target_distribution = {}
                for target in target_ips:
                    target_distribution[target] = target_distribution.get(target, 0) + 1
                
                # Ako je velika većina paketa usmerena na jednu IP adresu
                if target_distribution:
                    main_target = max(target_distribution, key=target_distribution.get)
                    main_target_count = target_distribution[main_target]
                    
                    if main_target_count / count > 0.7:  # 70% paketa ka istoj destinaciji
                        self.detected_attacks.append({
                            'type': 'DOS',
                            'severity': 'CRITICAL',
                            'source_ip': ip,
                            'target_ip': main_target,
                            'packet_count': count,
                            'description': f'Detektovan DoS napad: {count} paketa sa {ip} ka {main_target}',
                            'timestamp': datetime.now().isoformat()
                        })
    
    def _detect_suspicious_connections(self):
        """
        Pravilo 4: Detekcija sumnjivih konekcija
        Detektuje neobične obrasce konekcija
        """
        # Analiza konekcija na nestandardne portove
        suspicious_events = []
        
        # Lista standardnih portova
        standard_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432]
        
        for event in self.events:
            dst_port = event.get('dst_port')
            if dst_port and dst_port not in standard_ports and dst_port > 1024:
                suspicious_events.append(event)
        
        # Grupiranje po izvornoj IP adresi
        ip_suspicious_map = defaultdict(list)
        for event in suspicious_events:
            ip_suspicious_map[event['src_ip']].append(event)
        
        for ip, events in ip_suspicious_map.items():
            if len(events) > self.thresholds['connection_threshold']:
                unique_ports = set(e.get('dst_port') for e in events if e.get('dst_port'))
                
                self.detected_attacks.append({
                    'type': 'SUSPICIOUS_ACTIVITY',
                    'severity': 'LOW',
                    'source_ip': ip,
                    'connection_count': len(events),
                    'unusual_ports': list(unique_ports),
                    'description': f'Detektovana sumnjiva aktivnost sa {ip}: {len(events)} konekcija na nestandardne portove',
                    'timestamp': datetime.now().isoformat()
                })
    
    def get_attacks_by_severity(self, severity):
        """Filtrira napade po ozbiljnosti"""
        return [a for a in self.detected_attacks if a['severity'] == severity]
    
    def get_attacks_by_type(self, attack_type):
        """Filtrira napade po tipu"""
        return [a for a in self.detected_attacks if a['type'] == attack_type]
    
    def get_all_attacks(self):
        """Vraća sve detektovane napade"""
        return self.detected_attacks
    
    def print_summary(self):
        """Ispisuje sažetak detektovanih napada"""
        if not self.detected_attacks:
            print("\n✓ Nisu detektovani napadi")
            return
        
        print("\n" + "="*60)
        print("DETEKTOVANI NAPADI")
        print("="*60)
        
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        type_count = {}
        
        for attack in self.detected_attacks:
            severity_count[attack['severity']] += 1
            attack_type = attack['type']
            type_count[attack_type] = type_count.get(attack_type, 0) + 1
        
        print(f"\nUkupno napada: {len(self.detected_attacks)}")
        print("\nPo ozbiljnosti:")
        for severity, count in severity_count.items():
            if count > 0:
                print(f"  {severity}: {count}")
        
        print("\nPo tipu:")
        for attack_type, count in type_count.items():
            print(f"  {attack_type}: {count}")
        
        print("\nDetalji napada:")
        for i, attack in enumerate(self.detected_attacks, 1):
            print(f"\n{i}. [{attack['severity']}] {attack['type']}")
            print(f"   {attack['description']}")
            print(f"   Izvor: {attack['source_ip']}")


if __name__ == "__main__":
    # Test
    from pcap_loader import PcapLoader
    from log_extractor import LogExtractor
    from event_analyzer import EventAnalyzer
    
    loader = PcapLoader()
    count = loader.load_pcap("sample.pcap")
    
    if count > 0:
        parsed = [loader.parse_packet(p) for p in loader.get_all_packets()[:1000]]
        
        extractor = LogExtractor()
        events = extractor.extract_events(parsed)
        
        analyzer = EventAnalyzer()
        results = analyzer.analyze_events(events)
        
        detector = AttackDetector()
        attacks = detector.detect_attacks(events, results)
        detector.print_summary()