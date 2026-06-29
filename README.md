# codealpha_network_sniffer.py
Cybersecurity Intenship Projects
Here we capture network packets using python language.it capture network traffic in real time,extracts key information from the packets and preparesthe data.

*uses scapy's sniff function to monitor traffic
*analyze_packet() is used so that it triggers when a packet is captured
*then we check whether that packet has ip layer followed by identifying whether its TCP,UDP or ICMP packets
*then each of the data like source ip,destination ip,info and protocal are displayed via print().
