from scapy.all import *



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


            IP = host.split(' ')[0]
            MAC = host.split(' ')[1]
            
            print("{}.\t|\t{}\t|\t{}\t|".format(n, IP, MAC))



    def spoof(self, ip_num, spoof_ip):

        spoof_mac = self.get_mac(spoof_ip)
        
        self.table[ip_num] = self.table[ip_num].split(' ')[0] + " " + spoof_mac
        
        

        
        



        

        












        



    






