#!/usr/bin/python

from scapy.all import *
import sys

if __name__ == '__main__':
	object = rdpcap(sys.argv[1])
	for eachpacket in object:
		print eachpacket.show()
