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

def checkPort(ip, port):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(0.3)
		result = s.connect((ip, port))
		s.shutdown(1)
		if (port==7):
			print (str(port)+"\tOPEN\tECHO")
		elif (port==20):
			print (str(port)+"\tOPEN\tFTP DATA")
		elif (port==21):
			print (str(port)+"\tOPEN\tFTP")
		elif (port==23):
			print (str(port)+"\tOPEN\tTELNET")
		elif (port==25):
			print (str(port)+"\tOPEN\tSMTP")
		elif (port==37):
			print (str(port)+"\tOPEN\tTIME")
		elif (port==42):
			print (str(port)+"\tOPEN\tWINS")
		elif (port==43):
			print (str(port)+"\tOPEN\tWHOIS")
		elif (port==53):
			print (str(port)+"\tOPEN\tDNS")
		elif (port==80):
			print (str(port)+"\tOPEN\tHTTP")
		elif (port==115):
			print (str(port)+"\tOPEN\tWHOIS")
		elif (port==118):
			print (str(port)+"\tOPEN\tSQL")
		elif (port==143):
			print (str(port)+"\tOPEN\tIMAP")
		elif (port==162):
			print (str(port)+"\tOPEN\tSMNP TRAP")
		elif (port==194):
			print (str(port)+"\tOPEN\tIRC")
		elif (port==389):
			print (str(port)+"\tOPEN\tLDAP")
		elif (port==401):
			print (str(port)+"\tOPEN\tUPS")
		elif (port==443):
			print (str(port)+"\tOPEN\tHTTPS")
		elif (port==444):
			print (str(port)+"\tOPEN\tSNPP")
		elif (port==445):
			print (str(port)+"\tOPEN\tSMB")
		elif (port==465):
			print (str(port)+"\tOPEN\tSMB OVER SSL")
		elif (port==546):
			print (str(port)+"\tOPEN\tDHCP v6 CLIENT")
		elif (port==574):
			print (str(port)+"\tOPEN\tDHCP v6 SERVER")
		elif (port==631):
			print (str(port)+"\tOPEN\tIPP\t")
		elif (port==636):
			print (str(port)+"\tOPEN\tLDAPoSSL")
		elif (port==691):
			print (str(port)+"\tOPEN\tEXCHANGE ROUTING")
		elif (port==694):
			print (str(port)+"\tOPEN\tLINUX HA")
		else:
			print (str(port)+"\tOPEN")
	except:
		print (str(port)+"\tCLOSED")


def printHeader(ip,portrange):
	print ("\n** CHECKING "+ip+"\tPORT: "+portrange+ " **\n")

	print ("PORT\tSTATUS\tFUNCTION")
	print ("----\t------\t--------")

parser = argparse.ArgumentParser(description='Simple Portscanner')
parser.add_argument('-t','--target', help='Host IP or name', required=True)
parser.add_argument('-p','--port', help='Port (80) or List of ports (80,88,443) or portange(80-90)', required=True)
args = vars(parser.parse_args())

target = str(args['target'])
port = str(args['port'])

if "-" in port:
	printHeader(target,port)
	portrange = port.split('-')
	start = int(portrange[0])
	end = int(portrange[1])
	while start < end+1:
		checkPort(str(target), int(start))
		start = start + 1
	print ("")
elif "," in port:
	printHeader(target,port)
	portrange = port.split(',')
	for p in portrange:
		checkPort(str(target), int(p))
	print ("")
else:
	printHeader(target,port)
	checkPort(str(target), int(port))
	print ("")
