# Import necessary libraries
from scapy.all import *
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
import binascii
import time
import os
import re
import logging

# ASCII banner for Ionjector
banner = """
    ____              _           __            
   /  _/___  ____    (_)__  _____/ /_____  _____
   / // __ \/ __ \  / / _ \/ ___/ __/ __ \/ ___/
 _/ // /_/ / / / / / /  __/ /__/ /_/ /_/ / /    
/___/\____/_/ /_/_/ /\___/\___/\__/\____/_/     
               /___/                           
                             v1 by ionnoim
"""

# Display the banner when the script starts
print(banner)

# Global variables for storing the last packet details
last_packet = None
last_source_port = None
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

def des_encrypt(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_data = data.encode('utf-8').ljust(8, b'\0')
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data

# Enhanced Packet Crafting Function with conditional iface and spoofing options
def craft_and_send_packet(payload_text, target, protocol, encryption, interface, spoofing, custom_mac=None, custom_ip=None, key=None, header_options=None):
    """Crafts and sends a packet with optional spoofed source MAC and IP addresses."""
    try:
        # Determine encryption method
        if encryption == "none":
            payload = payload_text.encode('utf-8')
        elif encryption == "xor":
            payload = xor_encrypt(payload_text, key)
        elif encryption == "aes":
            if not key:
                key = get_random_bytes(16)  # AES requires 16-byte key
            payload = aes_encrypt(payload_text, key)
        elif encryption == "des":
            if not key:
                key = get_random_bytes(8)  # DES requires 8-byte key
            payload = des_encrypt(payload_text, key)
        else:
            print("Invalid encryption choice.")
            return
        
        # Craft Ethernet frame with optional spoofed MAC address
        if spoofing and custom_mac:
            eth_layer = Ether(src=custom_mac, dst="ff:ff:ff:ff:ff:ff")  # Set custom MAC as source
            print(f"Using spoofed MAC address: {custom_mac}")
        else:
            eth_layer = Ether(dst="ff:ff:ff:ff:ff:ff")  # Default broadcast MAC
            print("Using default broadcast MAC address.")
        
        # Create IP layer and apply spoofing if needed
        ip_layer = IP(dst=target, src=custom_ip if spoofing and custom_ip else None, **header_options.get("ip"))
        
        # Protocol-specific packet crafting with dynamic header options
        if protocol == "udp":
            udp_layer = UDP(dport=int(header_options["udp"]["dport"]), sport=int(header_options["udp"]["sport"]))
            packet = eth_layer/ip_layer/udp_layer/Raw(load=payload)
        elif protocol == "tcp":
            tcp_layer = TCP(dport=int(header_options["tcp"]["dport"]), sport=int(header_options["tcp"]["sport"]), flags=header_options["tcp"]["flags"])
            packet = eth_layer/ip_layer/tcp_layer/Raw(load=payload)
        elif protocol == "icmp":
            packet = eth_layer/ip_layer/ICMP()/Raw(load=payload)
        else:
            print("Unsupported protocol.")
            return

        # Save packet data for replay and flooding
        global last_packet_data
        last_packet_data = {  # Store packet data for replay and flood
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

        # Send the packet at Layer 2 to apply the spoofed MAC address
        sendp(packet, iface=interface)
        print(f"Packet crafted and sent with spoofed MAC {custom_mac if custom_mac else 'default'} on {interface}:\n{packet.summary()}\n")

    except Exception as e:
        logging.error(f"Error occurred while crafting or sending packet: {str(e)}")
        print(f"Failed to send packet: {str(e)}")

# Function to load payload from file
def load_payload_from_file(file_path):
    if os.path.isfile(file_path):
        with open(file_path, 'r') as file:
            return file.read().strip()
    else:
        print("File not found.")
        return None

# Function to replay the last crafted packet
def replay_last_packet():
    """Resends the last crafted packet using the stored configuration."""
    try:
        if not last_packet_data:
            print("No packet data available for replay.")
            return
        print("Replaying last crafted packet...")
        craft_and_send_packet(**last_packet_data)
    except Exception as e:
        logging.error(f"Error occurred while replaying packet: {str(e)}")
        print(f"Failed to replay packet: {str(e)}")

# Function to flood the last crafted packet
def flood_last_packet():
    """Floods the last crafted packet by repeatedly sending it."""
    try:
        if not last_packet_data:
            print("No packet data available for flooding.")
            return
        print("\nWARNING: Flooding can disrupt networks and devices.")
        print("Ensure you have full permission or ownership of the target devices.")
        consent = input("Do you accept responsibility? (yes/no): ").strip().lower()
        if consent != "yes":
            print("Flooding operation canceled.")
            return
        
        packet_count = int(input("Enter number of packets to send in the flood: "))
        print(f"Flooding {packet_count} packets to {last_packet_data['target']}...")
        for _ in range(packet_count):
            craft_and_send_packet(**last_packet_data)  # Resend the last packet repeatedly
        print("Flooding complete.")
    
    except Exception as e:
        logging.error(f"Error occurred during flooding: {str(e)}")
        print(f"Failed to flood packets: {str(e)}")

# Helper functions for user input
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

# Main Interface Loop
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
                # Target specifications
                target = input("Enter the target IP or MAC address: ")
                
                # Protocol choice
                protocol = get_choice("\nSelect Protocol:", ["tcp", "udp", "icmp", "ethernet"])
                
                # Payload entry
                input_method = get_choice("\nEnter Payload as:", ["Text", "File"])
                if input_method == "File":
                    file_path = input("Enter file path for payload: ")
                    payload_text = load_payload_from_file(file_path)
                    if payload_text is None:
                        continue
                else:
                    payload_text = input("Enter the payload to send: ")

                # Encryption choice
                encryption_choice = get_choice("\nSelect Encryption:", ["none", "xor", "aes", "des"])
                encryption_key = None
                if encryption_choice in ["xor", "aes", "des"]:
                    encryption_key = input("Enter encryption key (hexadecimal format) or leave blank to auto-generate: ")
                    if encryption_key:
                        encryption_key = bytes.fromhex(encryption_key)
                    elif encryption_choice in ["aes", "des"]:
                        encryption_key = get_random_bytes(16 if encryption_choice == "aes" else 8)
                
                # Spoofing option
                spoofing = get_choice("\nEnable Spoofing?", ["No", "Yes"]) == "Yes"
                custom_mac = input("Enter custom source MAC address (or leave blank): ") if spoofing else None
                custom_ip = input("Enter custom source IP address (or leave blank): ") if spoofing else None

                # Select Network Interface
                interface = input("Enter network interface (e.g., eth0, wlan0): ")
                
                # Header Options
                print("\n--- Header Options ---")
                header_options = {"ip": {}, protocol: {}}
                header_options["ip"]["ttl"] = int(input("Enter IP TTL (default 64): ") or 64)
                
                # Protocol-specific header fields
                if protocol == "tcp":
                    header_options["tcp"]["dport"] = input("Enter TCP destination port: ")
                    header_options["tcp"]["sport"] = input("Enter TCP source port: ")
                    header_options["tcp"]["flags"] = input("Enter TCP flags (e.g., 'S' for SYN): ")
                elif protocol == "udp":
                    header_options["udp"]["dport"] = input("Enter UDP destination port: ")
                    header_options["udp"]["sport"] = input("Enter UDP source port: ")

                craft_and_send_packet(payload_text, target, protocol, encryption_choice, interface, spoofing, custom_mac, custom_ip, encryption_key, header_options)
            
            except Exception as e:
                logging.error(f"Error in crafting packet: {str(e)}")
                print(f"Error occurred: {str(e)}")
        
        elif choice == '2':
            replay_last_packet()
        
        elif choice == '3':
            flood_last_packet()
        
        elif choice == '4':
            print("Exiting... Goodbye!")
            break
        
        else:
            print("Invalid choice. Please select 1, 2, 3, or 4.")
