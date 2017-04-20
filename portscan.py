#!/usr/bin/python

# Simple Portscan
# Christoph Franke
# mail@cfranke.org
# 20.04.2017
# Version 0.5

import socket
import argparse

def checkPort(ip, port):
    try: 
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        result = s.connect((ip, port))
        s.shutdown(1)
        print (str(port)+"\t\033[92mOPEN\033[0m")
    except: 
        print (str(port)+"\t\033[91mCLOSED \033[0m")

parser = argparse.ArgumentParser(description='Simple Portscanner')
parser.add_argument('-t','--target',help='Hostname or IPv4 address', required=True)
parser.add_argument('-p','--port',help='Port or Portrange', required=True)
args = vars(parser.parse_args())

target = str(args['target'])
port = str(args['port'])

print ("** Checking "+str(target)+" **\n")

print ("PORT\tSTATUS")
print ("----\t------")
if "-" in port: 
    portrange = port.split('-')
    start = int(portrange[0])
    end = int(portrange[1])
    while start < end+1:
        checkPort(str(target), int(start))
        start = start + 1

elif port=="common" or port=="cmn" or port=="c":
    port = "21,22,23,25,53,80,118,143,389,443,445,3389"
    portrange = port.split(',')
    for p in portrange:
        checkPort(str(target), int(p))

elif "," in port: 
    portrange = port.split(',')
    for p in portrange: 
        checkPort(str(target), int(p))

else:
    checkPort(str(target),int(port))

print ("")
