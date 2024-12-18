# Ionjector

![screenshot](ionjector.png)

Ionjector is a versatile packet injection tool designed for network security research, penetration testing, and network protocol experimentation. This application allows users to craft custom packets with flexible options for encryption, protocol selection, MAC/IP spoofing, and payload management. With features for packet replay and flooding, Ionjector is a powerful tool for testing network defenses and researching packet-based attacks within a controlled, legal environment.

## Features

![screenshot1](prot.png)
- **Custom Packet Crafting**: Create packets for TCP, UDP, ICMP, HTTP, FTP, DNS or Ethernet protocols.
- **Payload Encryption**: Choose from multiple encryption methods (`xor`, `aes`, `3des`, `des` and `blowfish`) for payloads.
- **MAC/IP Spoofing**: Modify source MAC and IP addresses for legal testing and research.
- **File-Based Payloads**: Load payloads from external files (text or binary) for efficient, reusable testing.
- **Replay and Flooding Capabilities**: Easily resend the last crafted packet or conduct flood testing to simulate high-volume network traffic.


## Disclaimer

**Ionjector is intended strictly for legal network research, educational, and ethical penetration testing purposes. Unauthorized use of this tool on networks or devices without permission is illegal and unethical.** The creators and maintainers of Ionjector assume no liability for any misuse of the application. By using Ionjector, users agree to take full responsibility for their actions and to ensure compliance with all applicable laws and regulations.


## Requirements

- Python 3.x
- [Scapy](https://scapy.net/) (for packet crafting and sending)
- [PyCryptodome](https://pycryptodome.readthedocs.io/) (for encryption support)

To install the required Python libraries, run:

```bash
pip install scapy pycryptodome
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ionnoim/Ionjector
   cd Ionjector
   ```

2. Make the script executable:
   ```bash
   chmod +x ionjector.py
   ```

3. Run Ionjector:
   ```bash
   python3 ionjector.py
   ```

## Example Usage

Here’s a quick example of how to use Ionjector to craft and send a packet.

1. **Launch Ionjector**:
   ```bash
   python3 ionjector.py
   ```

2. **Select `Send a crafted packet`**.

3. **Configure packet options**:
   - **Target**: Specify the IP or MAC address of the target.
   - **Protocol**: Choose between TCP, UDP, ICMP, HTTP, FTP, DNS or Ethernet.
   - **Payload**: Enter text directly or choose a file-based payload.
   - **Encryption**: Select `none`, `xor`, `aes`, `3des`, `des` or `blowfish`
   - **Spoofing**: Optionally spoof the source IP and/or MAC address.
   - **Interface**: Choose a network interface, such as `eth0` or `wlan0`.
   - **Flood and Replay**: Send multiple copies of the last packet or conduct a replay with prior configuration.

4. **Inspect with Wireshark or tcpdump** to confirm packet delivery and verify payload content.

### Testing File Payloads

File-based payloads can be tested by placing a file in the working directory and selecting it as the payload source. Example payloads:

- **Text Payload** (`payload.txt`):
  ```plaintext
  This is a test payload for my packet.
  ```
- **Binary Payload** (`binary_payload.bin`):
  ```bash
  echo -n -e "\xde\xad\xbe\xef" > binary_payload.bin
  ```

Specify the file path when prompted to use it as the packet payload.

## License

Ionjector is open-source software licensed under the [MIT License](LICENSE).

Thanks for taking an interest in my work! ionnoim@proton.me

Note: Planning to add a "Modify Payload and Resend" option soon for efficiency of use.
