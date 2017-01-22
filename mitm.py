from scapy.all import *
from scapy.contrib.modbus import *
import sys

iface = ""
filter = "ip"
VICTIM_IP = ""
MY_IP = ""
GATEWAY_IP = ""
VICTIM_MAC = ""
MY_MAC = ""
GATEWAY_MAC = ""

def debug(packet):
	if IP in packet:
		if TCP in packet:
			if packet[TCP].sport == 502 or packet[TCP].dport == 502:
				print packet.show2
				print "--------------------------------------------------------"

sniff(prn=debug, filter=filter, iface=iface, store=0)
