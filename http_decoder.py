#!/usr/bin/env python

"""

Description:
    The purpose of this tool was to extract the server banners from server 
    responses. Because this is HTTP traffic the tool filter for only TCP packets
    Then it digs into the raw TCP packets.
    
Usage:
    usage: python second.py <pcapfile>.pcap <csvfile>.csv

By Leo Kaestner

"""
import os
import sys # Used for arguments
import csv # used to read and write .csv files
from scapy.utils import RawPcapReader # The tool as mentioned in the ReadME.md
from scapy.layers.l2 import Ether # To convert packets to ethernet packets
from scapy.layers.inet import IP, TCP # To extract IP and TCP layers of packets
from scapy.packet import Raw # To extract raw data from packets

# This function creates a .csv file. The function takes in a string name for the
# file.
def createCSV(fileName):

    #Checks if a file with the same name already exists
    exists = os.path.isfile(fileName)
    if exists:
        sys.exit("File already exists.")
    else:
        with open(fileName, 'w', newline='') as csvFile:
            fWriter = csv.writer(csvFile, delimiter=',',
                                 quotechar='|', quoting=csv.QUOTE_MINIMAL)
            fWriter.writerow(['IP', 'Banner'])
        print("file %s has been created." % fileName)

# The main() function. This functions checks for a string name for the .csv file
# and a .pcap file. Each packet in the .pcap file is read using the
# RawPcapReader() function. Everything is filtered out everything but TCP packets.
def main(argv):

    #Variables that will be used.
    fileName = ''
    pcapFile = ''
    findings = {}
    ether_pkt = None
    tcp_pkt = None

    # Checks if a string name and pcap file is given to the tool.
    if(len(argv) == 3):
        pcapFile = argv[1]
        fileName = argv[2]
    else:
        sys.exit("usage: python second.py <pcapfile>.pcap <csvfile>.csv")

    # Checks if the .pcap file exists.
    exists = os.path.isfile(pcapFile)
    if not exists:
        sys.exit("ERROR: .pcap file does not exist...")
    else:
        print('Opening {}...'.format(pcapFile))

    # The .pcap file is read using RawPcapReader()
    reader = RawPcapReader(pcapFile)
    for(pkt_data, pkt_metadata,) in reader:

        #
        ether_pkt = Ether(pkt_data)

        if not ether_pkt.haslayer(TCP):
            continue
        else:
            tcp_pkt = TCP(ether_pkt)

        if tcp_pkt.haslayer(Raw):
            # Below prints the raw load of each TCP packet.
            #print (tcp_pkt[Raw].load)
            pass

    print(findings)

    # Execution ends here
    sys.exit(0)

# Where the execution of the code begins
if __name__ == "__main__":
    main(sys.argv)
