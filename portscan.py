#!/usr/bin/python
# portscan.py
# Christoph Franke
# mail@christophfranke.net
# 06.02.2015
# Version: 1.0

import argparse
import socket
import string
import sys
import os
import datetime
from prettytable import PrettyTable

x = PrettyTable(["Port", "Status", "Function"])
x.align["Port"] = "r"
x.align["Function"] = "l"
x.align["Status"] = "l"
x.padding_width = 1

def checkPort(ip, port):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(0.3)
		result = s.connect((ip, port))
		s.shutdown(1)
		if (port==7):
			#print (str(port)+"\tOPEN\tECHO")
			x.add_row([str(port),"OPEN","Echo"])
		elif (port==20):
			#print (str(port)+"\tOPEN\tFTP DATA")
			x.add_row([str(port),"OPEN","tFTP Data"])
		elif (port==21):
			#print (str(port)+"\tOPEN\tFTP")
			x.add_row([str(port),"OPEN","tFTP"])
		elif (port==22):
			#print (str(port)+"\tOPEN\tFTP")
			x.add_row([str(port),"OPEN","SSH"])
		elif (port==23):
			#print (str(port)+"\tOPEN\tTELNET")
			x.add_row([str(port),"OPEN","Telnet"])
		elif (port==25):
			#print (str(port)+"\tOPEN\tSMTP")
			x.add_row([str(port),"OPEN","SMTP"])
		elif (port==37):
			#print (str(port)+"\tOPEN\tTIME")
			x.add_row([str(port),"OPEN","Time"])
		elif (port==42):
			#print (str(port)+"\tOPEN\tWINS")
			x.add_row([str(port),"OPEN","WINS"])
		elif (port==43):
			#print (str(port)+"\tOPEN\tWHOIS")
			x.add_row([str(port),"OPEN","WHOIS"])
		elif (port==53):
			#print (str(port)+"\tOPEN\tDNS")
			x.add_row([str(port),"OPEN","DNS"])
		elif (port==80):
			#print (str(port)+"\tOPEN\tHTTP")
			x.add_row([str(port),"OPEN","HTTP"])
		elif (port==115):
			#print (str(port)+"\tOPEN\tWHOIS")
			x.add_row([str(port),"OPEN","WHOIS"])
		elif (port==118):
			#print (str(port)+"\tOPEN\tSQL")
			x.add_row([str(port),"OPEN","SQL"])
		elif (port==143):
			#print (str(port)+"\tOPEN\tIMAP")
			x.add_row([str(port),"OPEN","IMAP"])
		elif (port==162):
			#print (str(port)+"\tOPEN\tSMNP TRAP")
			x.add_row([str(port),"OPEN","SNMP Trap"])
		elif (port==194):
			#print (str(port)+"\tOPEN\tIRC")
			x.add_row([str(port),"OPEN","IRC"])
		elif (port==389):
			#print (str(port)+"\tOPEN\tLDAP")
			x.add_row([str(port),"OPEN","LDAP"])
		elif (port==401):
			#print (str(port)+"\tOPEN\tUPS")
			x.add_row([str(port),"OPEN","UPS"])
		elif (port==443):
			#print (str(port)+"\tOPEN\tHTTPS")
			x.add_row([str(port),"OPEN","HTTPS"])
		elif (port==444):
			#print (str(port)+"\tOPEN\tSNPP")
			x.add_row([str(port),"OPEN","SNPP"])
		elif (port==445):
			#print (str(port)+"\tOPEN\tSMB")
			x.add_row([str(port),"OPEN","SMP"])
		elif (port==465):
			#print (str(port)+"\tOPEN\tSMB OVER SSL")
			x.add_row([str(port),"OPEN","SMBoSSL"])
		elif (port==546):
			#print (str(port)+"\tOPEN\tDHCP v6 CLIENT")
			x.add_row([str(port),"OPEN","DHCPv6 Client"])
		elif (port==574):
			#print (str(port)+"\tOPEN\tDHCP v6 SERVER")
			x.add_row([str(port),"OPEN","DHCPv6 Server"])
		elif (port==631):
			#print (str(port)+"\tOPEN\tIPP\t")
			x.add_row([str(port),"OPEN","IPP"])
		elif (port==636):
			#print (str(port)+"\tOPEN\tLDAPoSSL")
			x.add_row([str(port),"OPEN","LDAPoSSL"])
		elif (port==691):
			#print (str(port)+"\tOPEN\tEXCHANGE ROUTING")
			x.add_row([str(port),"OPEN","Exchange Routing"])
		elif (port==694):
			#print (str(port)+"\tOPEN\tLINUX HA")
			x.add_row([str(port),"OPEN","Linux HA"])
		elif (port==3389):
			#print (str(port)+"\tOPEN\tLINUX HA")
			x.add_row([str(port),"OPEN","RDP"])
		else:
			#print (str(port)+"\tOPEN")
			x.add_row([str(port),"OPEN",""])
		if (logging==True):
			fw.write(target+","+str(port)+",OPEN\n")
	except:
		#print (str(port)+"\tCLOSED")
		x.add_row([str(port),"CLOSED",""])
		if (logging==True):
			fw.write(target+","+str(port)+",CLOSED\n")

#def printHeader(ip,portrange):
#	print ("\n** CHECKING "+ip+" PORT: "+portrange+ " **\n")
#
#	print ("PORT\tSTATUS\tFUNCTION")
#	print ("----\t------\t--------")

parser = argparse.ArgumentParser(description='Simple Portscanner')
parser.add_argument('-t','--target', help='Host IP or name', required=True)
parser.add_argument('-p','--port', help='Port (80) or List of ports (80,88,443) or portange(80-90)', required=True)
parser.add_argument('-l','--log', help='TRUE creates a comma-seperated-logfile')
args = vars(parser.parse_args())

target = str(args['target'])
port = str(args['port'])
log = str(args['log'])

if (log==None):
    logging=False
elif ((log=="True") or (log=="TRUE") or (log=="true")):
    logging=True
elif ((log=="False") or (log=="FALSE") or (log=="false")):
    logging=False
else:
    logging=False

ts= str(datetime.date.today())
if (logging==True):
    fw = open('portscan_'+ts+'.csv','w')
    fw.write("Host,Port,Status\n")

if "-" in port:
#	printHeader(target,port)
	portrange = port.split('-')
	start = int(portrange[0])
	end = int(portrange[1])
	while start < end+1:
		checkPort(str(target), int(start))
		start = start + 1
	print x
elif "," in port:
#	printHeader(target,port)
	portrange = port.split(',')
	for p in portrange:
		checkPort(str(target), int(p))
	print x
elif port=="std" or port=="go" or port=="hack" or port=="s":
	port = "21,22,23,25,53,80,118,143,389,443,3389"
	portrange = port.split(',')
	for p in portrange:
		checkPort(str(target), int(p))
	print x
else:
#	printHeader(target,port)
	checkPort(str(target), int(port))
	print x
