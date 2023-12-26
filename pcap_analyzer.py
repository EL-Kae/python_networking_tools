#!/usr/bin/env python

"""
Description:
    The goal of this tool was to log all unique IP addresses and count how
    many times each address participates in a full TCP handshake. 

    The tool logs all unique IP addresses that participated in the
    first step of the TCP handshake: send and recieving the SYN packet. The IPs are 
    paired with the default count of 0 in a .csv file.

Purpose:
    This tool will take in a pcap file, and log all unique IP address in a newly
    created .csv file. The user will need to provide the pcap file and a name
    for the .csv file. The reader checks if a packet has a IP and a TCP layer.
    If it does, the IP address is added to the findings{} dictionary. If the
    packet does not have an IP and a TCP layer there is no way for the packet to
    particpate in a TCP handshake so the reader moves on to the next packet.
    Only IP addresses participating in TCP traffic are logged.

Usage:
    python first.py <pcapfile>.pcap <csvfile>.csv

By Leo Kaestner

"""
import os
import sys # Needed to take in arguments
import csv # Needed to create and write to a .csv file
from scapy.utils import RawPcapReader # The tool as indicated by the ReadME.md
from scapy.layers.l2 import Ether # Needed To extract the Ethernet packet
from scapy.layers.inet import IP, TCP # Needed to extract the IP and TCP packet

# This function takes in a string as a filename and a dictionary of findings
# This function creates the .csv file and puts in the dictionary of IPs and
# and counts.
def createCSV(fileName, findings):

    # Checks if a file with the same name of the .csv already exists
    exists = os.path.isfile(fileName)
    if exists:
        sys.exit("File already exists.")
    else:
        with open(fileName, 'w', newline='') as csvFile:
            fWriter = csv.writer(csvFile, delimiter=',',
                                 quotechar='|', quoting=csv.QUOTE_MINIMAL)
            # Creates the header IP/Count as indicated by the README.md
            fWriter.writerow(['IP', 'Count'])

            # Writes the findings into the .csv file
            for key, value in findings.items():
                fWriter.writerow([key, value])
        print("file %s has been created." % fileName)


# The main() function. This is where the arguments are taken in, the pcap file
# is read and the IP addresses extracted. The .pcap file is read using the
# RawPcapReader() function. The raw packets are converted into Ethernet packets
# using Ether(). The IP and TCP packets are later extracted from the Ethernet
# packet. The IP addresses are extracted and passed into the createCSV() function
def main(argv):
    # Variables that will be used
    fileName = ''
    pcapFile = ''
    findings = {}
    ether_pkt = None
    ip_pkt = None
    tcp_pkt = None

    # Checks if a string name and a pcap file is provided
    if(len(argv) == 3):
        pcapFile = argv[1]
        fileName = argv[2]
    else:
        sys.exit("usage: python first.py <pcapFile>.pcap <csvFile>.csv")

    # Checks if the pcap file exists. If it does the code execution continues
    exists = os.path.isfile(pcapFile)
    if not exists:
        sys.exit("ERROR: .pcap file does not exist...")
    else:
        print('Opening {}...'.format(pcapFile))

    # the pcap file is read using RawPcapReader()
    reader = RawPcapReader(pcapFile)
    for(pkt_data, pkt_metadata,) in reader:

        #The raw packets are converted into ethernet packets
        ether_pkt = Ether(pkt_data)

        # If the packet does not have an IP layer, the reader moves on to the
        # next packet.
        if not ether_pkt.haslayer(IP):
            continue

        #The IP packet is extracted
        ip_pkt = ether_pkt.getlayer(IP)

        # If either the scr or dst IP address doesn't already exist in the
        # findings dictionary it will be added to it
        if ip_pkt.src not in findings:
            findings[ip_pkt.src] = 0
        if ip_pkt.dst not in findings:
            findings[ip_pkt.dst] = 0

        """
        Here packets start to get filtered out.

        # If the packet doesn't have a TCP layer, the reader moves on.
        if not ip_pkt.haslayer(TCP):
            continue

        # The tcp layer is extracted
        tcp_pkt = ip_pkt.getlayer(TCP)

        # The 0x002 is the flag for SYN packets
        if tcp_pkt.flags != 0x002:
            continue

        src = ip_pkt.src
        dst = ip_pkt.dst
        """

    # The csv file is created from the findings dictionary.
    createCSV(fileName, findings)

    #The execution ends here
    sys.exit(0)

# Where the execution starts. def main() is called with its arguments.
if __name__ == "__main__":
    main(sys.argv)
