from scapy.all import Ether, IP, TCP, UDP

def printIPPacket(hex_data):
    packet = IP(bytes.fromhex(hex_data))
    packet.show()

def printTCPPacket(hex_data):
    packet = IP(bytes.fromhex(hex_data))
    packet.show()

def printUDPPacket(hex_data):
    packet = UDP(bytes.fromhex(hex_data))
    packet.show()

def printEtherPacket(hex_data):
    packet = Ether(bytes.fromhex(hex_data))
    packet.show()

# Callback function to process each packet
def print_packet(packet):
    if packet.haslayer(TCP):
        if packet[TCP].dport == 8085 or packet[TCP].sport == 8085:  # Filter port 80
            #print(f"New Packet: {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")
            print(f"Flags: {packet[TCP].flags}")
            print(f"Sequence Number: {packet[TCP].seq}")
            print(f"Acknowledgment: {packet[TCP].ack}")
            print(f"Payload: {str(bytes(packet[TCP].payload))}")

# Sniff packets on all interfaces (or specify iface)
sniff(iface="lo0", prn=print_packet, store=False)
