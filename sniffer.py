from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP


def is_public_ip(ip):
    """Check if an IP is public (not private or special)."""
    private_ranges = [
        '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
        '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
        '0.', '255.255.255.255', '127.'
    ]
    return not any(ip.startswith(prefix) for prefix in private_ranges)

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        # Only print packets with at least one public IP
        if is_public_ip(src_ip) or is_public_ip(dst_ip):
            print(f"\nIP Packet: Source IP={src_ip}, Destination IP={dst_ip}, Protocol={packet[IP].proto}")
            if TCP in packet:
                print(f"TCP Packet: Source Port={packet[TCP].sport}, Dest Port={packet[TCP].dport}")
            elif UDP in packet:
                print(f"UDP Packet: Source Port={packet[UDP].sport}, Dest Port={packet[UDP].dport}")
            print(f"Raw Packet: {packet.summary()}")

def main():
    try:
        print("Starting Scapy sniffer for public IPs... Press Ctrl+C to stop")
        # Sniff on specific interface (replace 'Wi-Fi' with your interface name)
        sniff(iface='Wi-Fi', prn=packet_callback, store=0, filter="ip")
    except KeyboardInterrupt:
        print("\nSniffer stopped.")
    except Exception as e:
        print(f"Error occurred: {str(e)}")

if __name__ == "__main__":
    main()