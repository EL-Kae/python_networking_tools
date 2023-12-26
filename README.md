# python_networking_tools
A collection of networking tools created in python.

## PCAP Analyzer 
Processes a provided PCAP file packet-by-packet using [Scapy](https://scapy.net/)'s `RawPcapReader` class. For each unique IPv4 address it will count the number of unique TCP connections it participated in. The tool will only consider TCP connections for which a full handshake is observed. The output is a CSV file containing the IP/count data sorted in descending order.

## HTTP Decoder
This tool finds TCP connections that uses HTTP by analyzing the raw bytes of a TCP payload for signs of the HTTP protocol. It extracts the value of the Server response header field for each HTTP connection by processing each HTTP packet's TCP payload byte-by-byte. This is done by simple pattern matching. The output is a CSV file containing the IP address and server banner in the order the server names were observed.
