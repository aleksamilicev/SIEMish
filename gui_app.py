"""
GUI aplikacija za SIEM sistem
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.dates as mdates
import pandas as pd
from datetime import datetime
import threading
import numpy as np

from pcap_loader import PcapLoader
from log_extractor import LogExtractor
from event_analyzer import EventAnalyzer
from attack_detector import AttackDetector


class SIEMApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SIEM - Sistem za analizu i vizualizaciju log podataka")
        self.root.geometry("1400x900")
        
        # Inicijalizacija modula
        self.loader = PcapLoader()
        self.extractor = LogExtractor()
        self.analyzer = EventAnalyzer()
        self.detector = AttackDetector()
        
        # Podaci
        self.parsed_packets = []
        self.log_events = []
        self.analysis_results = {}
        self.detected_attacks = []
        
        # Status
        self.current_file = None
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Postavlja UI elemente"""
        
        # Gornji panel za kontrole
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill=tk.X)
        
        # Dugmići
        ttk.Button(control_frame, text="📁 Učitaj PCAP", 
                   command=self.load_file).pack(side=tk.LEFT, padx=5)
        
        self.extract_btn = ttk.Button(control_frame, text="🔍 Ekstrahuj logove", 
                                       command=self.extract_logs, state=tk.DISABLED)
        self.extract_btn.pack(side=tk.LEFT, padx=5)
        
        self.analyze_btn = ttk.Button(control_frame, text="📊 Analiziraj", 
                                       command=self.analyze_events, state=tk.DISABLED)
        self.analyze_btn.pack(side=tk.LEFT, padx=5)
        
        self.detect_btn = ttk.Button(control_frame, text="🛡️ Detektuj napade", 
                                      command=self.detect_attacks, state=tk.DISABLED)
        self.detect_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="🚀 Pokreni sve", 
                   command=self.run_all).pack(side=tk.LEFT, padx=5)
        
        # Label za trenutni fajl
        self.file_label = ttk.Label(control_frame, text="Nijedan fajl nije učitan")
        self.file_label.pack(side=tk.LEFT, padx=20)
        
        # Progress bar
        self.progress = ttk.Progressbar(control_frame, mode='indeterminate')
        self.progress.pack(side=tk.RIGHT, padx=5, fill=tk.X, expand=True)
        
        # Status bar
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, padx=10)
        
        self.status_labels = {}
        statuses = [
            ("pcap", "PCAP učitan", "gray"),
            ("logs", "Logovi ekstrahovani", "gray"),
            ("analysis", "Analiza završena", "gray"),
            ("attacks", "Napadi detektovani", "gray")
        ]
        
        for key, text, color in statuses:
            label = tk.Label(status_frame, text=f"● {text}", 
                           bg=color, fg="white", padx=10, pady=3)
            label.pack(side=tk.LEFT, padx=5, pady=5)
            self.status_labels[key] = label
        
        # Notebook za tabove
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab 1: Pregled
        self._setup_overview_tab()
        
        # Tab 2: Log događaji
        self._setup_events_tab()
        
        # Tab 3: Analiza
        self._setup_analysis_tab()
        
        # Tab 4: Napadi
        self._setup_attacks_tab()
        
        # Tab 5: Vizualizacija
        self._setup_visualization_tab()
        
        # Konzola na dnu
        console_frame = ttk.LabelFrame(self.root, text="Konzolni izlaz", padding="5")
        console_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.console = tk.Text(console_frame, height=8, bg="#0f1419", fg="#00ff00",
                              font=("Courier", 9), wrap=tk.WORD)
        self.console.pack(fill=tk.BOTH, expand=True)
        
        self.log("Sistem spreman za rad.")
    
    def _setup_overview_tab(self):
        """Tab sa pregledom"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📊 Pregled")
        
        # Stat kartice
        stats_frame = ttk.Frame(frame)
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.stat_cards = {}
        stats = [
            ("packets", "Ukupno paketa", "0"),
            ("events", "Log događaja", "0"),
            ("ips", "Jedinstvenih IP", "0"),
            ("attacks", "Napada", "0")
        ]
        
        for key, label, value in stats:
            card = ttk.LabelFrame(stats_frame, text=label, padding="10")
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
            
            val_label = tk.Label(card, text=value, font=("Arial", 24, "bold"))
            val_label.pack()
            
            self.stat_cards[key] = val_label
        
        # Info text
        info = tk.Text(frame, wrap=tk.WORD, height=20, font=("Arial", 10))
        info.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        info.insert("1.0", """
DOBRODOŠLI U SIEM SISTEM

Ovaj sistem omogućava analizu mrežnog saobraćaja kroz 5 modula:

1. UČITAVANJE I PARSIRANJE
   - Učitava .pcap fajlove
   - Parsira mrežne pakete
   
2. EKSTRAKCIJA LOGOVA
   - Normalizuje događaje
   - Identifikuje tipove (SSH, HTTP, FTP, RDP...)
   
3. ANALIZA FREKVENTNOSTI
   - Agregira po IP adresama
   - Analizira portove i protokole
   
4. DETEKCIJA NAPADA
   - Bruteforce (>50 pokušaja)
   - Port Scanning (>5 portova)
   - DoS (>100 paketa)
   
5. VIZUALIZACIJA
   - Grafikoni i statistike
   - Upozorenja o napadima

Kliknite "Učitaj PCAP" da počnete.
        """)
        info.config(state=tk.DISABLED)
    
    def _setup_events_tab(self):
        """Tab sa događajima"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📝 Log događaji")
        
        # Treeview
        tree_frame = ttk.Frame(frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        columns = ("timestamp", "event_type", "src_ip", "dst_ip", "dst_port", "protocol")
        self.events_tree = ttk.Treeview(tree_frame, columns=columns, 
                                       show="headings", yscrollcommand=vsb.set)
        
        vsb.config(command=self.events_tree.yview)
        
        headers = ["Vreme", "Tip događaja", "Izvorna IP", "Odredišna IP", "Port", "Protokol"]
        for col, header in zip(columns, headers):
            self.events_tree.heading(col, text=header)
            self.events_tree.column(col, width=120)
        
        self.events_tree.pack(fill=tk.BOTH, expand=True)
    
    def _setup_analysis_tab(self):
        """Tab sa analizom"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📈 Analiza")
        
        self.analysis_text = tk.Text(frame, wrap=tk.WORD, font=("Courier", 10))
        self.analysis_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def _setup_attacks_tab(self):
        """Tab sa napadima"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🛡️ Napadi")
        
        # Treeview
        tree_frame = ttk.Frame(frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        columns = ("type", "severity", "source_ip", "description")
        self.attacks_tree = ttk.Treeview(tree_frame, columns=columns, 
                                        show="headings", yscrollcommand=vsb.set)
        
        vsb.config(command=self.attacks_tree.yview)
        
        headers = ["Tip napada", "Ozbiljnost", "Izvorna IP", "Detalji"]
        for col, header in zip(columns, headers):
            self.attacks_tree.heading(col, text=header)
            self.attacks_tree.column(col, width=200)
        
        self.attacks_tree.pack(fill=tk.BOTH, expand=True)
    
    def _setup_visualization_tab(self):
        """Tab sa vizualizacijom"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📉 Vizualizacija")
        
        self.fig = Figure(figsize=(12, 8))
        self.canvas = FigureCanvasTkAgg(self.fig, master=frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def log(self, message):
        """Dodaje poruku u konzolu"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.insert(tk.END, f"[{timestamp}] {message}\n")
        self.console.see(tk.END)
    
    def update_status(self, key, active):
        """Ažurira status indikator"""
        if key in self.status_labels:
            color = "green" if active else "gray"
            self.status_labels[key].config(bg=color)
    
    def load_file(self):
        """Učitava PCAP fajl"""
        file_path = filedialog.askopenfilename(
            title="Izaberite PCAP fajl",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        self.current_file = file_path
        self.file_label.config(text=f"Fajl: {file_path.split('/')[-1]}")
        self.log(f"Učitavanje: {file_path}")
        
        self.progress.start()
        threading.Thread(target=self._load_thread, args=(file_path,), daemon=True).start()
    
    def _load_thread(self, file_path):
        """Thread za učitavanje"""
        try:
            count = self.loader.load_pcap(file_path)
            
            if count > 0:
                # Parsiranje
                self.root.after(0, lambda: self.log(f"Parsiranje {count:,} paketa..."))
                
                self.parsed_packets = []
                for packet_info in self.loader.parse_packets_batch(count=min(count, 100000)):
                    self.parsed_packets.append(packet_info)
                
                self.root.after(0, self._load_complete, len(self.parsed_packets))
            else:
                self.root.after(0, lambda: messagebox.showerror("Greška", "Fajl je prazan"))
                self.root.after(0, self.progress.stop)
        
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Greška", str(e)))
            self.root.after(0, self.progress.stop)
    
    def _load_complete(self, count):
        """Callback nakon učitavanja"""
        self.progress.stop()
        self.update_status("pcap", True)
        self.extract_btn.config(state=tk.NORMAL)
        self.stat_cards["packets"].config(text=f"{count:,}")
        self.log(f"✓ Učitano {count:,} paketa")
        messagebox.showinfo("Uspeh", f"Učitano {count:,} paketa")
    
    def extract_logs(self):
        """Ekstrahuje logove"""
        self.log("Ekstrakcija log događaja...")
        self.progress.start()
        threading.Thread(target=self._extract_thread, daemon=True).start()
    
    def _extract_thread(self):
        """Thread za ekstrakciju"""
        try:
            self.log_events = self.extractor.extract_events(self.parsed_packets)
            self.root.after(0, self._extract_complete)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Greška", str(e)))
            self.root.after(0, self.progress.stop)
    
    def _extract_complete(self):
        """Callback nakon ekstrakcije"""
        self.progress.stop()
        self.update_status("logs", True)
        self.analyze_btn.config(state=tk.NORMAL)
        self.stat_cards["events"].config(text=f"{len(self.log_events):,}")
        
        # Popuni tabelu
        for event in self.log_events[:1000]:
            timestamp = datetime.fromisoformat(event['timestamp']).strftime('%H:%M:%S')
            self.events_tree.insert("", tk.END, values=(
                timestamp,
                event['event_type'],
                event['src_ip'],
                event['dst_ip'],
                event.get('dst_port', 'N/A'),
                event['protocol']
            ))
        
        self.log(f"✓ Ekstrahovano {len(self.log_events):,} događaja")
        messagebox.showinfo("Uspeh", f"Ekstrahovano {len(self.log_events):,} događaja")
    
    def analyze_events(self):
        """Analizira događaje"""
        self.log("Analiza frekventnosti...")
        self.progress.start()
        threading.Thread(target=self._analyze_thread, daemon=True).start()
    
    def _analyze_thread(self):
        """Thread za analizu"""
        try:
            self.analysis_results = self.analyzer.analyze_events(self.log_events)
            self.root.after(0, self._analyze_complete)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Greška", str(e)))
            self.root.after(0, self.progress.stop)
    
    def _analyze_complete(self):
        """Callback nakon analize"""
        self.progress.stop()
        self.update_status("analysis", True)
        self.detect_btn.config(state=tk.NORMAL)
        
        ip_count = len(self.analysis_results['ip_frequency']['source_ips'])
        self.stat_cards["ips"].config(text=str(ip_count))
        
        # Prikaži rezultate
        text = "="*70 + "\n"
        text += "REZULTATI ANALIZE\n"
        text += "="*70 + "\n\n"
        
        text += f"Ukupno događaja: {len(self.log_events):,}\n\n"
        
        text += "TOP 10 IZVORNIH IP:\n" + "-"*70 + "\n"
        for ip, count in list(self.analysis_results['ip_frequency']['source_ips'].items())[:10]:
            text += f"  {ip:20s} {count:6,} paketa\n"
        
        text += "\nPROTOKOLI:\n" + "-"*70 + "\n"
        for protocol, count in self.analysis_results['protocol_distribution'].items():
            pct = (count / len(self.log_events)) * 100
            text += f"  {protocol:10s} {count:6,} paketa ({pct:5.2f}%)\n"
        
        self.analysis_text.delete("1.0", tk.END)
        self.analysis_text.insert("1.0", text)
        
        self.log("✓ Analiza završena")
        messagebox.showinfo("Uspeh", "Analiza završena")
    
    def detect_attacks(self):
        """Detektuje napade"""
        self.log("Detekcija napada...")
        self.progress.start()
        threading.Thread(target=self._detect_thread, daemon=True).start()
    
    def _detect_thread(self):
        """Thread za detekciju"""
        try:
            self.detected_attacks = self.detector.detect_attacks(
                self.log_events, self.analysis_results
            )
            self.root.after(0, self._detect_complete)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Greška", str(e)))
            self.root.after(0, self.progress.stop)
    
    def _detect_complete(self):
        """Callback nakon detekcije"""
        self.progress.stop()
        self.update_status("attacks", True)
        self.stat_cards["attacks"].config(text=str(len(self.detected_attacks)))
        
        # Popuni tabelu napada
        for attack in self.detected_attacks:
            self.attacks_tree.insert("", tk.END, values=(
                attack['type'],
                attack['severity'],
                attack['source_ip'],
                attack['description']
            ))
        
        # Vizualizuj
        self.create_visualizations()
        
        if len(self.detected_attacks) > 0:
            self.log(f"⚠ Detektovano {len(self.detected_attacks)} napada!")
            messagebox.showwarning("Napadi!", f"Detektovano {len(self.detected_attacks)} napada!")
        else:
            self.log("✓ Nisu detektovani napadi")
            messagebox.showinfo("Sistem siguran", "Nisu detektovani napadi")
    
    def create_visualizations(self):
        """Kreira sve vizualizacije"""
        self.fig.clear()
        
        gs = self.fig.add_gridspec(2, 3, hspace=0.3, wspace=0.3)
        
        # 1. Top IP adrese
        ax1 = self.fig.add_subplot(gs[0, 0])
        self._plot_top_ips(ax1)
        
        # 2. Protokoli
        ax2 = self.fig.add_subplot(gs[0, 1])
        self._plot_protocols(ax2)
        
        # 3. Top portovi
        ax3 = self.fig.add_subplot(gs[0, 2])
        self._plot_top_ports(ax3)
        
        # 4. Vremenska distribucija
        ax4 = self.fig.add_subplot(gs[1, 0])
        self._plot_time_distribution(ax4)
        
        # 5. Napadi po tipu
        ax5 = self.fig.add_subplot(gs[1, 1])
        self._plot_attack_types(ax5)
        
        # 6. Napadi po severity
        ax6 = self.fig.add_subplot(gs[1, 2])
        self._plot_attack_severity(ax6)
        
        self.canvas.draw()
    
    def _plot_top_ips(self, ax):
        """Grafikon top IP adresa"""
        source_ips = self.analysis_results['ip_frequency']['source_ips']
        top_ips = list(source_ips.items())[:10]
        
        if top_ips:
            ips, counts = zip(*top_ips)
            y_pos = np.arange(len(ips))
            ax.barh(y_pos, counts, color='#3b82f6')
            ax.set_yticks(y_pos)
            ax.set_yticklabels(ips, fontsize=8)
            ax.invert_yaxis()
            ax.set_xlabel('Broj paketa', fontsize=9)
            ax.set_title('Top 10 izvornih IP adresa', fontsize=10, fontweight='bold')
            ax.grid(axis='x', alpha=0.3)
    
    def _plot_protocols(self, ax):
        """Pie chart protokola"""
        protocols = self.analysis_results['protocol_distribution']
        
        if protocols:
            labels = list(protocols.keys())
            sizes = list(protocols.values())
            colors = ['#3b82f6', '#ef4444', '#10b981', '#f59e0b']
            ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors)
            ax.set_title('Distribucija protokola', fontsize=10, fontweight='bold')
    
    def _plot_top_ports(self, ax):
        """Grafikon top portova"""
        dest_ports = self.analysis_results['port_frequency']['destination_ports']
        top_ports = list(dest_ports.items())[:10]
        
        if top_ports:
            ports, counts = zip(*top_ports)
            x_pos = np.arange(len(ports))
            ax.bar(x_pos, counts, color='#10b981')
            ax.set_xticks(x_pos)
            ax.set_xticklabels(ports, rotation=45, fontsize=8)
            ax.set_ylabel('Broj paketa', fontsize=9)
            ax.set_title('Top 10 odredišnih portova', fontsize=10, fontweight='bold')
            ax.grid(axis='y', alpha=0.3)
    
    def _plot_time_distribution(self, ax):
        """Vremenska distribucija"""
        time_dist = self.analysis_results['time_distribution']
        
        if time_dist:
            times = [datetime.strptime(t, '%Y-%m-%d %H:%M') for t in time_dist.keys()]
            counts = list(time_dist.values())
            ax.plot(times, counts, color='#ef4444', linewidth=2)
            ax.fill_between(times, counts, alpha=0.3, color='#ef4444')
            ax.set_xlabel('Vreme', fontsize=9)
            ax.set_ylabel('Broj događaja', fontsize=9)
            ax.set_title('Frekventnost kroz vreme', fontsize=10, fontweight='bold')
            ax.grid(True, alpha=0.3)
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
            plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, fontsize=8)
    
    def _plot_attack_types(self, ax):
        """Distribucija napada"""
        if not self.detected_attacks:
            ax.text(0.5, 0.5, 'Nisu detektovani napadi', 
                   ha='center', va='center', fontsize=12)
            ax.set_title('Distribucija napada', fontsize=10, fontweight='bold')
            return
        
        attack_types = {}
        for attack in self.detected_attacks:
            t = attack['type']
            attack_types[t] = attack_types.get(t, 0) + 1
        
        types = list(attack_types.keys())
        counts = list(attack_types.values())
        
        colors_map = {
            'BRUTEFORCE': '#ef4444',
            'PORT_SCAN': '#f59e0b',
            'DOS': '#dc2626',
            'SUSPICIOUS_ACTIVITY': '#6b7280'
        }
        colors = [colors_map.get(t, '#6b7280') for t in types]
        
        ax.bar(types, counts, color=colors)
        ax.set_ylabel('Broj napada', fontsize=9)
        ax.set_title('Napadi po tipu', fontsize=10, fontweight='bold')
        plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, ha='right', fontsize=8)
        ax.grid(axis='y', alpha=0.3)
    
    def _plot_attack_severity(self, ax):
        """Ozbiljnost napada"""
        if not self.detected_attacks:
            ax.text(0.5, 0.5, 'Nisu detektovani napadi', 
                   ha='center', va='center', fontsize=12)
            ax.set_title('Ozbiljnost napada', fontsize=10, fontweight='bold')
            return
        
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for attack in self.detected_attacks:
            severity_count[attack['severity']] += 1
        
        labels = [s for s in severity_count.keys() if severity_count[s] > 0]
        sizes = [severity_count[s] for s in labels]
        
        colors_map = {
            'CRITICAL': '#dc2626',
            'HIGH': '#ef4444',
            'MEDIUM': '#f59e0b',
            'LOW': '#9ca3af'
        }
        colors = [colors_map[s] for s in labels]
        
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors)
        ax.set_title('Ozbiljnost napada', fontsize=10, fontweight='bold')
    
    def run_all(self):
        """Pokreće kompletan pipeline"""
        file_path = filedialog.askopenfilename(
            title="Izaberite PCAP fajl",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        self.current_file = file_path
        self.file_label.config(text=f"Fajl: {file_path.split('/')[-1]}")
        
        self.log("Pokretanje kompletnog pipeline-a...")
        self.progress.start()
        threading.Thread(target=self._pipeline_thread, args=(file_path,), daemon=True).start()
    
    def _pipeline_thread(self, file_path):
        """Thread za kompletan pipeline"""
        try:
            # 1. Učitavanje
            self.root.after(0, lambda: self.log("[1/4] Učitavanje..."))
            count = self.loader.load_pcap(file_path)
            
            self.parsed_packets = []
            for packet_info in self.loader.parse_packets_batch(count=min(count, 100000)):
                self.parsed_packets.append(packet_info)
            
            self.root.after(0, self.update_status, "pcap", True)
            self.root.after(0, lambda: self.stat_cards["packets"].config(text=f"{len(self.parsed_packets):,}"))
            
            # 2. Ekstrakcija
            self.root.after(0, lambda: self.log("[2/4] Ekstrakcija..."))
            self.log_events = self.extractor.extract_events(self.parsed_packets)
            self.root.after(0, self.update_status, "logs", True)
            self.root.after(0, lambda: self.stat_cards["events"].config(text=f"{len(self.log_events):,}"))
            
            # 3. Analiza
            self.root.after(0, lambda: self.log("[3/4] Analiza..."))
            self.analysis_results = self.analyzer.analyze_events(self.log_events)
            self.root.after(0, self.update_status, "analysis", True)
            ip_count = len(self.analysis_results['ip_frequency']['source_ips'])
            self.root.after(0, lambda: self.stat_cards["ips"].config(text=str(ip_count)))
            
            # 4. Detekcija
            self.root.after(0, lambda: self.log("[4/4] Detekcija..."))
            self.detected_attacks = self.detector.detect_attacks(
                self.log_events, self.analysis_results
            )
            self.root.after(0, self.update_status, "attacks", True)
            self.root.after(0, lambda: self.stat_cards["attacks"].config(text=str(len(self.detected_attacks))))
            
            self.root.after(0, self._pipeline_complete)
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Greška", str(e)))
            self.root.after(0, self.progress.stop)
    
    def _pipeline_complete(self):
        """Callback nakon pipeline-a"""
        self.progress.stop()
        
        # Popuni sve tabele
        for event in self.log_events[:1000]:
            timestamp = datetime.fromisoformat(event['timestamp']).strftime('%H:%M:%S')
            self.events_tree.insert("", tk.END, values=(
                timestamp, event['event_type'], event['src_ip'],
                event['dst_ip'], event.get('dst_port', 'N/A'), event['protocol']
            ))
        
        for attack in self.detected_attacks:
            self.attacks_tree.insert("", tk.END, values=(
                attack['type'], attack['severity'],
                attack['source_ip'], attack['description']
            ))
        
        # Vizualizuj
        self.create_visualizations()
        
        self.log("✓ Pipeline završen!")
        messagebox.showinfo("Uspeh", 
            f"Pipeline kompletiran!\n\n"
            f"Paketa: {len(self.parsed_packets):,}\n"
            f"Događaja: {len(self.log_events):,}\n"
            f"Napada: {len(self.detected_attacks)}"
        )


if __name__ == "__main__":
    root = tk.Tk()
    app = SIEMApp(root)
    root.mainloop()