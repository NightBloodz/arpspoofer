from scapy.all import *
import copy


class arptable:
    
    

    def __init__(self, ip, table):

        self.ip = ip
        self.table = table



    def get_mac(self, ip):
        arp_request = ARP(pdst = ip)
        broadcast = Ether(dst ="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
        return answered_list[0][1].hwsrc



    def show(self):
            
        print(self.ip + " ARP TABLE:\n")
        print("\t|\t\tIP\t|\t\tMAC\t\t|")

        for n, host in enumerate(self.table):


            IP = host[0]
            MAC = host[1]
            
            print("\n{}.\t|\t{}\t|\t{}\t|".format(n, IP, MAC), end=" ")
            
            if host[2]:
                print("\t(Spoofed)", end=" ")
            

    def spoof(self):

        self.show()

        row = int(input("\n> Select a row to spoof > "))

        spoof_ip = input("> MAC in row " + str(row) + " will be replaced with the MAC of (IP) > ")
        spoof_mac = self.get_mac(spoof_ip)

        
        self.table[row][1] = spoof_mac
        self.table[row][2] = True


        self.show()



    def mitm(self):
        pass

    

        


        

    
        
        

        
        



        

        












        



    






