#!/usr/bin/python

def FilterDns(object):
	''' '''
	dnspacket = []
	for eachpacket in object:
		if eachpacket['Ethernet'].type == 0x800:
			if eachpacket['IP'].proto == 17:
				if eachpacket['UDP'].sport == 53 or eachpacket['UDP'].dport == 53:
					dnspacket.append(eachpacket['DNS'])	
	return dnspacket
