# Public IP Packet Sniffer

A Python-based network packet sniffer built using the [Scapy](https://scapy.net/) library. This tool captures IP packets on a specified network interface and filters for those involving at least one public IP address, displaying details such as source and destination IPs, protocol, and TCP/UDP port numbers. It is designed for educational purposes and authorized network analysis by security professionals and enthusiasts.

## Features

- **Packet Capture**: Captures IP packets in real-time from a specified network interface.
- **Public IP Filtering**: Filters packets to display only those with at least one public IP, excluding private (e.g., `192.168.x.x`, `10.x.x.x`) and special (e.g., `0.0.0.0`, `255.255.255.255`) IP addresses.
- **Protocol Support**: Analyzes TCP and UDP packets, displaying source and destination ports.
- **Real-Time Output**: Prints packet details and summaries to the terminal.
- **Cross-Platform**: Compatible with Windows, Linux, and macOS with appropriate dependencies.

## Prerequisites

- **Python 3.8+**: Ensure Python is installed on your system.
- **Scapy**: Python library for packet manipulation.
- **Npcap (Windows)**: Required for packet capture on Windows. Download from [https://npcap.com](https://npcap.com).
- **Administrative Privileges**: Required to capture packets (e.g., run as administrator on Windows or with `sudo` on Linux/macOS).

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Cybernuel/public-ip-sniffer.git
   cd public-ip-sniffer
   ```

2. **Install Scapy**:
   ```bash
   pip install scapy
   ```

3. **Install Npcap (Windows Only)**:
   - Download and install Npcap from [https://npcap.com](https://npcap.com).
   - During installation, enable "Support raw 802.11 traffic" and "Support loopback traffic" if needed for capturing wireless or loopback traffic.

4. **Identify Network Interface**:
   - List available network interfaces using:
     ```python
     from scapy.all import get_if_list
     print(get_if_list())
     ```
   - Note the name of your active interface (e.g., `Wi-Fi`, `Ethernet`, `eth0`).

## Usage

1. **Save the Script**:
   - Save the provided script as `public_ip_sniffer.py`.

2. **Configure the Interface**:
   - Edit the script to specify your network interface. Replace `'Wi-Fi'` in the `sniff()` function with your interface name:
     ```python
     sniff(iface='Your-Interface-Name', prn=packet_callback, store=0, filter="ip")
     ```

3. **Run the Sniffer**:
   - Execute the script with administrative privileges:
     ```bash
     sudo python public_ip_sniffer.py
     ```
   - On Windows, run as administrator via Command Prompt or PowerShell (right-click and select "Run as administrator").
   - The sniffer will start capturing packets with public IPs.

4. **Generate Network Traffic**:
   - To capture packets with public IPs, generate internet traffic (e.g., browse a website, run `ping 8.8.8.8`, or stream a video).

5. **Example Output**:
   ```
   Starting Scapy sniffer for public IPs... Press Ctrl+C to stop

   IP Packet: Source IP=192.168.1.100, Destination IP=8.8.8.8, Protocol=1
   Raw Packet: Ether / IP / ICMP 192.168.1.100 > 8.8.8.8 echo-request 0

   IP Packet: Source IP=142.250.190.14, Destination IP=192.168.1.100, Protocol=6
   TCP Packet: Source Port=443, Dest Port=54321
   Raw Packet: Ether / IP / TCP 142.250.190.14:https > 192.168.1.100:54321 S
   ```

6. **Stop the Sniffer**:
   - Press `Ctrl+C` to stop capturing packets.

## Configuration

- **Network Interface**:
  - Modify the `iface` parameter in the `sniff()` function to target your specific network interface (e.g., `Wi-Fi`, `eth0`).
- **Packet Filter**:
  - The script uses a BPF filter (`filter="ip"`) to capture only IP packets. You can modify this to focus on specific protocols, e.g., `filter="tcp"` for TCP packets or `filter="udp"` for UDP packets. See [Scapy documentation](https://scapy.readthedocs.io/en/latest/usage.html#filtering) for advanced filter options.
- **Public IP Filtering**:
  - The `is_public_ip()` function excludes private and special IP ranges. To customize which IPs are considered private, edit the `private_ranges` list in the script:
    ```python
    private_ranges = [
        '10.', '192.168.', '172.16.', ..., '0.', '255.255.255.255', '127.'
    ]
    ```

## Ethical Use

This tool is intended for **educational purposes** and **authorized network analysis**. Unauthorized packet sniffing or monitoring may violate local, state, or federal laws. Ensure you have explicit permission to capture traffic on any network you monitor. The developers are not responsible for misuse or damages caused by this tool.

## Troubleshooting

- **No Packets Captured**:
  - Verify administrative privileges (run as administrator on Windows or with `sudo` on Linux/macOS).
  - Ensure Npcap is installed (Windows) or libpcap is available (Linux/macOS).
  - Confirm the correct interface name using `scapy.all.get_if_list()`.
  - Generate internet traffic (e.g., `ping 8.8.8.8`) to ensure packets with public IPs are sent/received.
- **Permission Error**:
  - Run the script with elevated privileges.
- **No Public IPs**:
  - Check if your network uses NAT (common in home routers), which may hide public IPs.
  - Ensure internet traffic is being generated (e.g., browse a website or ping an external server).
- **Error Messages**:
  - If errors occur, note the message and check for missing dependencies or incorrect interface names.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m "Add your feature"`).
4. Push to your branch (`git push origin feature/your-feature`).
5. Open a pull request.

Suggested improvements:
- Support for additional protocols (e.g., ICMP, ARP).
- Logging packets to a file for later analysis.
- Adding a user interface (e.g., CLI or GUI).
- Enhanced filtering for specific IP ranges or ports.

Please follow PEP 8 guidelines and include comments in your code.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Scapy](https://scapy.net/), a powerful packet manipulation library.
- Inspired by open-source network analysis tools.
