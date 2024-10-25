# Import necessary libraries
from scapy.all import *
from Crypto.Cipher import AES, DES, DES3, Blowfish
from Crypto.Random import get_random_bytes
import binascii
import time
import os
import logging

# ASCII banner for Ionjector
banner = r"""
    ____              _           __            
   /  _/___  ____    (_)__  _____/ /_____  _____
   / // __ \/ __ \  / / _ \/ ___/ __/ __ \/ ___/
 _/ // /_/ / / / / / /  __/ /__/ /_/ /_/ / /####-------- ',.  
/___/\____/_/ /_/_/ /\___/\___/\__/\____/_/     
               /___/                           
                             v1 by ionnoim
"""

# Display the banner when the script starts
print(banner)

# Global variables for storing the last packet details
last_packet_data = {}  # Dictionary to store last packet configuration

# Logging setup for error tracking only
logging.basicConfig(filename="packet_ionjector.log", level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")

# Encryption functions
def xor_encrypt(data, key=-85):
    data_bytes = data.encode('utf-8')
    encrypted_bytes = bytearray(data_bytes)
    for i in range(len(encrypted_bytes)):
        encrypted_bytes[i] ^= key & 0xFF
        key = encrypted_bytes[i]
    return bytes(encrypted_bytes)

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    encrypted_data, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return nonce + encrypted_data

# DES encryption function with padding for block alignment
def des_encrypt(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    # Pad the data to ensure it's a multiple of the DES block size (8 bytes)
    padded_data = data.encode('utf-8')
    while len(padded_data) % 8 != 0:
        padded_data += b' '  # Padding with spaces
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data

def triple_des_encrypt(data, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_data = data.encode('utf-8').ljust(24, b'\0')  # Padding to fit block size
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data

def blowfish_encrypt(data, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    padded_data = data.encode('utf-8').ljust(8, b'\0')  # Padding to fit block size
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data

# Function to handle encryption based on user choice
def apply_encryption(data, encryption, key=None):
    if encryption == "none":
        return data.encode('utf-8')
    elif encryption == "xor":
        return xor_encrypt(data)
    elif encryption == "aes":
        return aes_encrypt(data, key if key else get_random_bytes(16))
    elif encryption == "des":
        return des_encrypt(data, key if key else get_random_bytes(8))
    elif encryption == "3des":
        return triple_des_encrypt(data, key if key else get_random_bytes(24))
    elif encryption == "blowfish":
        return blowfish_encrypt(data, key if key else get_random_bytes(16))
    else:
        print("Invalid encryption choice.")
        return None

# Function to load payload from a file
def load_payload_from_file(file_path):
    """Loads the payload from a specified file path."""
    try:
        with open(file_path, 'r') as file:
            payload = file.read()
        return payload
    except Exception as e:
        logging.error(f"Error loading payload from file: {str(e)}")
        print(f"Error loading payload from file: {str(e)}")
        return None

# Protocol-Specific Crafting Functions
def craft_http_packet(target, method="GET", payload='', headers=None, custom_ip=None):
    # Ask user to input HTTP method and User-Agent if not provided
    if headers is None:
        headers = {}
    headers['User-Agent'] = input("Enter User-Agent (default 'Ionjector'): ") or 'Ionjector'
    method = input("Enter HTTP Method (default 'GET'): ") or method
    
    # Adjust payload handling for GET requests
    if method.upper() == "GET" and not payload:
        payload = '\n'  # Adding minimal payload to prevent retransmissions

    # Format headers with proper line endings
    request = f"{method} / HTTP/1.1\r\n" + ''.join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n" + payload

    # Force the HTTP packet to use port 80 for the destination and format payload for HTTP
    tcp_layer = TCP(dport=80, sport=RandShort(), flags='PA')  # 'PA' sets PSH and ACK
    return IP(dst=target, src=custom_ip)/tcp_layer/Raw(load=request.encode('utf-8'))

def craft_ftp_packet(target_ip, command, args, custom_ip=None):
    ftp_payload = f"{command} {args}\r\n".encode('utf-8')
    return IP(dst=target_ip, src=custom_ip)/TCP(dport=21)/Raw(load=ftp_payload)

def craft_dns_packet(domain, target_ip="8.8.8.8", custom_ip=None):
    return IP(dst=target_ip, src=custom_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype='A'))

# Main Crafting Function for Generic Packets
def craft_and_send_packet(payload_text, target, protocol, encryption, interface, spoofing, custom_mac=None, custom_ip=None, key=None, header_options=None):
    try:
        # Apply encryption if specified
        payload = apply_encryption(payload_text, encryption, key)
        if payload is None:
            return

        # Craft the packet with spoofed IP and/or MAC addresses if applicable
        if spoofing and custom_mac:
            eth_layer = Ether(src=custom_mac)
        else:
            eth_layer = Ether()  # Default Ethernet layer if no custom MAC

        # Protocol-specific packet construction with IP spoofing where needed
        if protocol == "http":
            packet = eth_layer / craft_http_packet(target, payload_text, custom_ip=custom_ip)
            sendp(packet, iface=interface)
        elif protocol == "ftp":
            packet = eth_layer / craft_ftp_packet(target, "USER", payload_text, custom_ip=custom_ip)
            sendp(packet, iface=interface)
        elif protocol == "dns":
            packet = eth_layer / craft_dns_packet(payload_text, target, custom_ip=custom_ip)
            sendp(packet, iface=interface)
        elif protocol == "udp":
            udp_layer = UDP(dport=int(header_options["udp"]["dport"]), sport=int(header_options["udp"]["sport"]))
            packet = eth_layer / IP(dst=target, src=custom_ip) / udp_layer / Raw(load=payload)
            sendp(packet, iface=interface)
        elif protocol == "tcp":
            tcp_layer = TCP(dport=int(header_options["tcp"]["dport"]), sport=int(header_options["tcp"]["sport"]), flags=header_options["tcp"]["flags"])
            packet = eth_layer / IP(dst=target, src=custom_ip) / tcp_layer / Raw(load=payload)
            sendp(packet, iface=interface)
        elif protocol == "icmp":
            packet = eth_layer / IP(dst=target, src=custom_ip) / ICMP() / Raw(load=payload)
            sendp(packet, iface=interface)
        elif protocol == "ethernet":
            packet = Ether(dst=custom_mac) / Raw(load=payload) if spoofing and custom_mac else Ether() / Raw(load=payload)
            sendp(packet, iface=interface)  # Ethernet at Layer 2
        else:
            print("Protocol not recognized.")
            return

        # Send confirmation
        print(f"Packet crafted and sent on {interface}:\n{packet.summary()}\n")

        # Save last packet for replay and flood
        global last_packet_data
        last_packet_data = {
            "payload_text": payload_text,
            "target": target,
            "protocol": protocol,
            "encryption": encryption,
            "interface": interface,
            "spoofing": spoofing,
            "custom_mac": custom_mac,
            "custom_ip": custom_ip,
            "key": key,
            "header_options": header_options
        }

    except Exception as e:
        logging.error(f"Error occurred: {str(e)}")
        print(f"Failed to send packet: {str(e)}")

# Helper function for user selection
def get_choice(prompt, choices):
    """Displays numbered choices and gets a valid integer choice from the user."""
    print(prompt)
    for idx, choice in enumerate(choices, start=1):
        print(f"{idx}. {choice}")
    while True:
        try:
            selection = int(input("Enter your choice: "))
            if 1 <= selection <= len(choices):
                return choices[selection - 1]
            else:
                print("Invalid choice. Please enter a number from the list.")
        except ValueError:
            print("Invalid input. Please enter a number.")

# Main Interface
if __name__ == "__main__":
    while True:
        print("\n--- Main Menu ---")
        print("1. Send a crafted packet")
        print("2. Replay last packet")
        print("3. Flood last packet")
        print("4. Exit")
        choice = input("Choose an option (1/2/3/4): ")

        if choice == '1':
            try:
                target = input("Enter target IP or MAC address: ")
                protocol = get_choice("\nSelect Protocol:", ["tcp", "udp", "icmp", "ethernet", "http", "ftp", "dns"])
                
                input_method = get_choice("\nPayload type:", ["Text", "File"])
                
                if input_method == "File":
                    payload_text = load_payload_from_file(input("File path: "))
                else:
                    payload_text = input("Payload to send: ")

                encryption_choice = get_choice("\nSelect Encryption:", ["none", "xor", "aes", "des", "3des", "blowfish"])
                
                # Only prompt for encryption key if encryption is not "none"
                encryption_key = None
                if encryption_choice != "none":
                    encryption_key_input = input("Enter encryption key (hex or blank): ")
                    encryption_key = bytes.fromhex(encryption_key_input) if encryption_key_input else None
                
                spoofing = get_choice("\nEnable Spoofing?", ["No", "Yes"]) == "Yes"
                if spoofing:
                    custom_mac = input("Custom MAC (blank for default): ")
                    custom_ip = input("Custom IP (blank for default): ")
                else:
                    custom_mac = None
                    custom_ip = None

                interface = input("Enter network interface (e.g., eth0): ")
                
                header_options = {"ip": {}, protocol: {}}
                header_options["ip"]["ttl"] = int(input("Enter IP TTL (default 64): ") or 64)
                
                if protocol in ["tcp", "udp"]:
                    header_options[protocol]["dport"] = input(f"Enter {protocol.upper()} destination port: ")
                    header_options[protocol]["sport"] = input(f"Enter {protocol.upper()} source port: ")
                    if protocol == "tcp":
                        header_options["tcp"]["flags"] = input("Enter TCP flags (e.g., 'S' for SYN): ")

                craft_and_send_packet(payload_text, target, protocol, encryption_choice, interface, spoofing, custom_mac, custom_ip, encryption_key, header_options)

            except Exception as e:
                logging.error(f"Error in crafting packet: {str(e)}")
                print(f"Error occurred: {str(e)}")

        elif choice == '2':
            # Replay the last packet
            if last_packet_data:
                craft_and_send_packet(**last_packet_data)
            else:
                print("No previous packet data available for replay.")
        
        elif choice == '3':
            # Flood the last crafted packet
            if last_packet_data:
                print("\nWARNING: Flooding can disrupt networks and devices.")
                print("Ensure you have full permission or ownership of the target devices.")
                consent = input("Do you accept responsibility? (yes/no): ").strip().lower()
                
                if consent == "yes":
                    packet_count = int(input("Enter number of packets to flood: "))
                    for _ in range(packet_count):
                        craft_and_send_packet(**last_packet_data)
                    print("Flooding complete.")
                else:
                    print("Flooding operation canceled.")
            else:
                print("No previous packet data available for flooding.")

        elif choice == '4':
            print("Exiting... Goodbye!")
            break
