from scapy.all import sniff, IP, TCP, UDP, ICMP
from colorama import Fore, Style, init

init(autoreset=True)

def packet_callback(packet):
    if packet.haslayer(IP):

        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            protocol = Fore.RED + "TCP"
        elif packet.haslayer(UDP):
            protocol = Fore.BLUE + "UDP"
        elif packet.haslayer(ICMP):
            protocol = Fore.YELLOW + "ICMP"
        else:
            protocol = Fore.WHITE + "Other"

        print(Fore.GREEN + "Source IP: " + Style.RESET_ALL + src)
        print(Fore.CYAN + "Destination IP: " + Style.RESET_ALL + dst)
        print(Fore.MAGENTA + "Protocol: " + protocol)
        print(Fore.WHITE + "-------------------------------------")

print(Fore.YELLOW + "Starting Colorful Network Sniffer...\n")

sniff(prn=packet_callback, count=20)