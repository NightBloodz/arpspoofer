from pwn import log
from scapy.all import *
import sys
import argparse
from tabulate import tabulate
import netifaces
from tables import *



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

host_list = []
    
arptables = {}
adapter = False
    



def arp_scan(network):
    
    hosts_up = []

    conf.verb = 0

    print("Scanning network (ARP)...")
    
    up, down = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = network), timeout = 3, iface = adapter, inter = 0.1)

    for snd,rcv in up:
        IP = str(rcv).split(' ')[7]
        MAC = str(rcv).split(' ')[5]
        hosts_up.append([IP, MAC, False])
        
            
    return hosts_up
        
    
  
def show_hosts(host_list):
    
    header = ["IP", "MAC", "HACKED"]

    print(tabulate(host_list, headers = header,  tablefmt="grid"))
       

        

        

adapter = sys.argv[1]



attacker_ip = netifaces.ifaddresses(adapter)[2][0]["addr"]    
attacker_mac = netifaces.ifaddresses(adapter)[17][0]["addr"]



attacker_addr = [attacker_ip, attacker_mac]
        
        
while adapter:

    #Read input user
    msg = input("\n\n> ")

    

    

    
        




    
    


    

    
        
   

        

        

        

        
        

        
        

        

        
        


        





    
            

