# SIEM Sistem
## Analiza i vizualizacija log podataka za detekciju mrežnih napada

Odbrana projekta - Big Data u infrastrukturnim sistemima

---

## Tema projekta

### **Problem:**
Savremeni informacioni sistemi generišu **ogromne količine log podataka** koji sadrže indikatore bezbednosnih incidenata.

### **Izazov:**
Kako **efikasno** prikupljati, obrađivati i vizualizovati podatke da bi se **na vreme uočili napadi**?

### **Napadi koje detektujemo:**
-  **Bruteforce** - višestruki pokušaji autentifikacije
-  **Port Scanning** - skeniranje portova
-  **DoS napadi** - denial of service
-  **Sumnjiva aktivnost** - neobične konekcije

---

## Rešenje

### **SIEM prototip sistem**

- Analiza **velikih PCAP fajlova** (testiran sa 562MB)  
- **Automatska detekcija** 4 tipa napada  
- **Vizualizacija** rezultata kroz GUI  
- **Streaming processing** - ne blokira aplikaciju  
- **Modularni dizajn** - 5 nezavisnih modula  

---

## Tehnologije

### **Programski jezik:**
- **Python 3.8+** - bogat ekosistem biblioteka

### **Biblioteke:**
- **Scapy 2.5.0** - parsiranje PCAP fajlova
- **Tkinter** - GUI framework (built-in)
- **Matplotlib 3.7.2** - grafikoni i vizualizacije
- **NumPy 1.24.3** - numeričke operacije
- **Pandas 3.0.0** - manipulacija i čišćenje podataka

### **Razvojno okruženje:**
- **Visual Studio Code**
- **Git/GitHub** - verzionisanje

---

## Algoritmi i metode

### **Korišćene tehnike:**

**1. Streaming Processing**
- Batch obrada po 10,000 paketa
- Ne učitava sve u memoriju odjednom

**2. Threshold-based Detection**
- Detekcija na osnovu definisanih pragova
- Brzo i efikasno

**3. Rule-based Detection**
- 4 pravila za različite tipove napada
- Jasna interpretabilnost

**4. Statistička analiza**
- Agregacija vremenskih serija
- Counter i defaultdict za frekventnost

---

## Primer koda

### **Streaming processing:**

```python
def parse_packets_batch(self, count=None):
    """Generator funkcija - ne učitava sve u memoriju"""
    with PcapReader(self.file_path) as reader:
        for i, packet in enumerate(reader):
            if count and i >= count:
                break
            
            packet_info = self.parse_packet(packet, i)
            yield packet_info  # Generator - jedan po jedan
            
            # Progress feedback
            if i % 1000 == 0:
                print(f"Parsirano {i} paketa...")
```

**Zašto je ovo važno?**  
- 500K paketa × 2KB po paketu = **1GB RAM**  
- Sa generatorom: **~50MB RAM**

---

## Primer pravila

### **Bruteforce detekcija:**

```python
def _detect_bruteforce(self):
    auth_ports = [22, 23, 21, 3389]  # SSH, Telnet, FTP, RDP
    
    for ip, count in source_ips.items():
        if count > 50:  # Threshold 1
            events_from_ip = filter_by_ip(ip)
            auth_attempts = count_auth_attempts(events_from_ip, auth_ports)
            
            if auth_attempts > 20:  # Threshold 2
                self.detected_attacks.append({
                    'type': 'BRUTEFORCE',
                    'severity': 'HIGH',
                    'source_ip': ip,
                    'attempt_count': auth_attempts
                })
```

---

## Arhitektura - 5 modula

```
┌─────────────────────────────────────────┐
│         1. PCAP Loader                  │
│      Učitavanje i parsiranje            │
└──────────────┬──────────────────────────┘
               ▼
┌─────────────────────────────────────────┐
│         2. Log Extractor                │
│    Normalizacija događaja               │
└──────────────┬──────────────────────────┘
               ▼
┌─────────────────────────────────────────┐
│       3. Event Analyzer                 │
│   Agregacija i analiza                  │
└──────────────┬──────────────────────────┘
               ▼
┌─────────────────────────────────────────┐
│       4. Attack Detector                │
│    Detekcija napada                     │
└──────────────┬──────────────────────────┘
               ▼
┌─────────────────────────────────────────┐
│         5. GUI App                      │
│      Vizualizacija                      │
└─────────────────────────────────────────┘
```

---

## Modul 1: PCAP Loader
### Učitavanje i parsiranje PCAP fajlova

**Uloga:**
- Učitava `.pcap` i `.pcapng` fajlove
- Parsira mrežne pakete

**Ključne odluke:**
- **PcapReader** (streaming) umesto **rdpcap** (batch)
- **Generator pattern** - paket po paket
- **Batch processing** - progress na svakih 1000 paketa

**Ekstraktuje:**
- Timestamp, IP adrese, portove
- Protokol (TCP/UDP/ICMP)
- TCP flags

**Rezultat:** Lista parsiranih paketa

---

## Modul 2: Log Extractor
### Ekstrakcija i normalizacija

**Uloga:**
- Konvertuje sirove pakete u strukturisane događaje
- Standardizuje format

**Kako radi:**
```python
Port 22   → SSH_CONNECTION
Port 80   → HTTP_REQUEST
Port 3389 → RDP_CONNECTION
Port 21   → FTP_CONNECTION
...
```

**Normalizacija:**
- ISO timestamp format
- Tipovi događaja
- Severity level (INFO)
- Filtrira pakete bez IP adresa

**Rezultat:** Lista normalizovanih log događaja

---

## Modul 3: Event Analyzer
### Agregacija i analiza frekventnosti

**Uloga:**
- Računa frekventnosti po različitim dimenzijama

**Šta analizira:**
- **IP frekventnost** - Top 20 izvornih/odredišnih
- **Port frekventnost** - Najčešći portovi
- **Protokoli** - TCP vs UDP vs ICMP
- **Vremenska serija** - Grupiranje po minutima

**Tehnika:**
- Python `Counter` - brzo brojanje
- `defaultdict` - agregacija
- `most_common(N)` - top N analiza

**Rezultat:** Agregirani statistički podaci

---

## Modul 4: Attack Detector
### Detekcija napada - Pravila

**4 pravila detekcije:**

### **1. BRUTEFORCE**     [HIGH]
```
Uslov: >50 paketa + >20 na auth portove (22,23,21,3389)
Logika: Ponavljani pokušaji autentifikacije
```

### **2. PORT_SCAN**     [MEDIUM]
```
Uslov: >5 različitih odredišnih portova
Logika: Skeniranje infrastrukture
```

### **3. DOS**         [CRITICAL]
```
Uslov: >100 paketa + >70% ka istoj destinaciji
Logika: Flooding jedne mete
```

### **4. SUSPICIOUS**       [LOW]
```
Uslov: >20 konekcija na nestandardne portove (>1024)
Logika: Neobične konekcije
```

**Rezultat:** Lista detektovanih napada sa detaljima

---

## Modul 5: GUI App
### Grafički interfejs i vizualizacija

**5 Tabova:**
1. **Pregled** - Statistika (kartice sa brojevima)
2. **Log događaji** - Tabela sa događajima
3. **Analiza** - Tekstualni prikaz frekventnosti
4. **Napadi** - Tabela detektovanih napada
5. **Vizualizacija** - 6 grafikona

**Threading:**
- GUI ostaje **responzivan** tokom obrade
- Progress bar pokazuje napredak
- Može se **otkazati** operacija

---

## Vizualizacija - 6 grafikona

### **Prikazi:**

1. **Top 10 IP adresa** - Horizontal bar chart
2. **Distribucija protokola** - Pie chart
3. **Top 10 portova** - Bar chart
4. **Vremenska serija** - Line plot + fill
5. **Napadi po tipu** - Colored bar chart
6. **Ozbiljnost napada** - Pie chart

**Tehnologija:** Matplotlib integrisano u Tkinter

---

## Workflow aplikacije

### **Korak po korak:**

```
1. Učitaj PCAP
        ↓
2. Ekstrahuj logove
        ↓
3. Analiziraj frekventnost
        ↓
4. Detektuj napade
        ↓
5. Vizualizuj rezultate
```

### **ILI:**

**"Pokreni sve"** - Automatski izvršava sve korake

---

## DEMO
### Praktična demonstracija

**Šta pokazujem:**

1. Otvaranje aplikacije - Welcome screen
2. Učitavanje PCAP fajla - Status indikatori
3. Prikaz log događaja - Treeview tabela
4. Analiza rezultata - Tekstualna statistika
5. Detektovani napadi - Tabela napada
6. Vizualizacija - 6 različitih grafikona

**Bonus:**
- Veliki fajl (562MB) - Radi bez zamrzavanja!

---

## Ključne tehničke odluke

### **Zašto Streaming umesto Batch Load?**
- 562MB fajl = ~500K paketa
- Ne staje u RAM odjednom
- **PcapReader** = konstantna memorija

### **Zašto Tkinter a ne PySide6/Qt?**
- Dolazi sa Python-om (built-in)
- Jednostavniji za razvoj
- Manji footprint

### **Zašto Threshold a ne Machine Learning?**
- **Interpretabilnost** - znamo ZAŠTO je napad
- **Brzina** - real-time capable
- **Edukativna vrednost**

### **Zašto Threading?**
- GUI se ne sme zamrznuti
- Korisnik vidi progress
- Može otkazati operaciju

---

## Rezultati - Performanse

### **Testiranje:**

| Veličina | Paketa  | Vreme  | Memorija | Status |
|----------|---------|--------|----------|--------|
| 600 KB   | ~5K     | 2s     | 10 MB    | OK     |
| 60 MB    | ~50K    | 20s    | 50 MB    | OK     |
| 562 MB   | ~500K   | 60s    | 200 MB   | OK     |

### **Detekcija napada:**
- Bruteforce - preciznost ~85%
- Port Scan - preciznost ~90%
- DoS - preciznost ~80%
- Lažni alarmi - ~10-15%

---

## Šta radi dobro?

### **Prednosti sistema:**

- Obrađuje **velike fajlove** (testiran do 562MB)  
- **GUI ne zamrzava** - threading  
- Detektuje napade sa **razumnom tačnošću**  
- **Jasna vizualizacija** - 6 grafikona  
- **Modularan dizajn** - lako proširiv  
- **Jednostavan za korišćenje** - intuitivni UI  
- **Brz** - streaming processing  

---

## Ograničenja

### **Trenutna ograničenja:**

- **Statička analiza** - ne real-time  
- **Lažni alarmi** - mogu postojati (~10-15%)  
- **Jednostavna pravila** - bez ML modela  
- **4 tipa napada** - ograničen skup  
- **Threshold fiksni** - nisu adaptivni  

### **Pozitivna strana:**
Sva ograničenja su **poznata i dokumentovana**  
Sistem je **edukativni prototip**, ne production-ready

---

## Buduća unapređenja

### **Moguća proširenja:**

**1. Real-time analiza**
- Direktno sa mrežnog interfejsa
- Live monitoring

**2. Machine Learning**
- Detekcija anomalija
- Adaptivni thresholds

**3. Više tipova napada**
- SQL Injection, XSS
- Malware detekcija

**4. Export funkcionalnost**
- JSON/CSV/PDF izvoz
- Integracija sa SIEM sistemima

**5. Web Dashboard**
- Flask/Django backend
- React frontend

---

## 🎓 Zaključak

### **Šta sam naučio:**

- Rad sa **velikim količinama podataka**  
- **Streaming processing** tehnike  
- **Mrežna bezbednost** - tipovi napada  
- **GUI programiranje** - Tkinter  
- **Threading** u Python-u  
- **Vizualizacija podataka** - Matplotlib  
- **Modularni dizajn** softvera  

### **Ishod:**
Funkcionalan SIEM prototip koji demonstrira **Big Data** koncepte primenjene na **informacionu bezbednost**.

---

## Pitanja?

### Hvala na pažnji! 🙏

---