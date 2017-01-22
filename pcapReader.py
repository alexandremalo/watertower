#! /usr/bin/env python
from scapy.all import *
from scapy.contrib.modbus import *
# ...
myreader = PcapReader(mycapturefile)
for p in myreader:
    pkt = p.payload
    print pkt.time
    print pkt.show2
