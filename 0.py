from scapy.all import *
import ssl

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        
        # Filtrace pouze HTTPS provozu (port 443)
        if dport == 443 or sport == 443:
            print(f"HTTPS Packet captured from {ip_src}:{sport} to {ip_dst}:{dport}")
            
            # Zobrazíme obsah paketu
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                try:
                    # Pokusíme se dekódovat, pokud je to nějaký HTTP požadavek
                    print(raw_data.decode(errors="ignore"))
                except:
                    pass

# Naslouchání na všech paketech na síti (v tomto případě pro port 443)
sniff(filter="tcp port 443", prn=packet_callback, store=0)
