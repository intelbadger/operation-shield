from scapy.all import rdpcap, Raw

# Load the pcap file
packets = rdpcap("shield.pcap") #you can change file name and file path instead of "shield.pcap"

# Extract readable ASCII text from packet payloads
extracted_text = []
for packet in packets:
    if Raw in packet:
        payload_data = packet[Raw].load.decode('ascii', errors='ignore')
        if payload_data.strip():
            extracted_text.append(payload_data.strip())

# Save to text file
with open("extracted_text1.txt", "w") as f:
    f.write("\n".join(extracted_text))
