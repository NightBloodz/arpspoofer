from scapy.all import *

class arptable:
    
    def __init__(self, ip, table):

        self.ip = ip
        self.table = table
         

    def show(self):
            
        print(self.ip + " ARP TABLE:\n")
        print("\t|\t\tIP\t|\t\tMAC\t\t|")

        for n, host in enumerate(self.table):


            IP = host.split(' ')[0]
            MAC = host.split(' ')[1]
            
            print("{}.\t|\t{}\t|\t{}\t|".format(n, IP, MAC))



    def spoof(self, ip_num, spoof_ip):

        spoof_mac = get_mac(spoof_ip)
        
        self.table[ip_num] = spoof_ip + " " + spoof_mac + " " + "(Spoofed)"
        

        
        



        

        












        



    






