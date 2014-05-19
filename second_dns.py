#!/usr/bin/python

import os
import sys
from scapy.all import *

def Filelist(object):
	'''List all pcap files in this directory'''
	filelist = os.listdir(object)
	allfilelist = []
	for eachfile in filelist:
		if eachfile.split('.')[-1] == 'pcap':
			allfilelist.append(eachfile)
	if allfilelist:
		return allfilelist
	else:
		print "This dirctory has not pcap files"
		sys.exit()

def FilterDns(object):
	'''Remain DNS packets '''
	dnspacket = []
	for eachpacket in object:
		if eachpacket['Ethernet'].type == 0x800:
			if eachpacket['IP'].proto == 17:
				if eachpacket['UDP'].sport == 53 or eachpacket['UDP'].dport == 53:
					dnspacket.append(eachpacket['DNS'])
	return dnspacket

def dns_statics(object):
	'''Save each query in dictionary. Key is query name. Values are rrname, type, ttl and rdata'''
	dnsstatics = {}
	dns = {}
	for eachdns in object:
		if eachdns.id in dnsstatics:
			if dnsstatics[eachdns.id].qr == 0 and eachdns.qr == 1:
				dnsstatics[eachdns.id]= eachdns
		else:
			dnsstatics[eachdns.id]= eachdns
	for values in dnsstatics.itervalues():
		if values.qd.qname in dns:
			if dns[values.qd.qname] == 'No Response': 
				if values.qr == 1:
					dnslist = []
					for i in range(values.ancount):
						dnslisttemp = []
						dnslisttemp.append(values.an[i].rrname)
						if values.an[i].type == 1:
							dnslisttemp.append('A')
						else:
							dnslisttemp.append('CNAME')
						dnslisttemp.append(values.an[i].ttl)
						dnslisttemp.append(values.an[i].rdata)
						dnslist.append(dnslisttemp)
					dns[values.qd.qname] = dnslist
			else:
				for i in range(values.ancount):
					temp = []
					if values.an[i].type == 1:
						temp = [values.an[i].rrname, 'A', values.an[i].ttl, values.an[i].rdata]
					else:	
						temp = [values.an[i].rrname, 'CNAME', values.an[i].ttl, values.an[i].rdata]
					if temp not in dnslist:
						dns[values.qd.qname].append(temp)
		else:
			if values.qr == 0:
				dns[values.qd.qname]= 'No Response'
			else:
				dnslist=[]
				for i in range(values.ancount):
					dnslisttemp = []
				 	dnslisttemp.append(values.an[i].rrname)
					if values.an[i].type == 1:
						dnslisttemp.append('A')
					else:
						dnslisttemp.append('CNAME')
					dnslisttemp.append(values.an[i].ttl)
					dnslisttemp.append(values.an[i].rdata)
					dnslist.append(dnslisttemp)
				dns[values.qd.qname] = dnslist
	return dns	

def PrintDnsOfEachPcap(object):
	for (k,v) in object.iteritems():
		print '-------------------------------------'
		print 'Query Name: %s' % k
		if v != 'No Response':
			for eachvalues in v:
				print 'rrname: %s' % eachvalues[0]
				print 'type: %s' % eachvalues[1]
				print 'TTL: %d' % eachvalues[2]
				print 'rdata: %s' % eachvalues[3]
		else:
			print 'No Response'
		print '-------------------------------------'



if __name__ == '__main__':
	if os.path.isfile(sys.argv[1]):
		if sys.argv[1].split('.')[-1] != 'pcap':
			print 'This file is not a pcap file'
			sys.exit()
		else:
			object = rdpcap(sys.argv[1])
			dns = dns_statics(FilterDns(object))
			PrintDnsOfEachPcap(dns)
	else:
		filelist = Filelist(sys.argv[1])
		secondleveldns = {}
		for list in filelist:
			object = rdpcap(sys.argv[1]+'/'+list)
			dns = dns_statics(FilterDns(object))
			#PrintDnsOfEachPcap(dns)
			for  dnskey in dns.iterkeys():
				pcapsecondleveldns = {}
				if dnskey.split('.')[-3] not in secondleveldns:
					dnslist = []
					dnslist.append(dnskey)
					pcapsecondleveldns[list] = dnslist
					secondleveldns[dnskey.split('.')[-3]] = pcapsecondleveldns
				else:
					if list not in secondleveldns[dnskey.split('.')[-3]].keys():
						dnslist = []
						dnslist.append(dnskey)
						secondleveldns[dnskey.split('.')[-3]][list] = dnslist
					else:
						secondleveldns[dnskey.split('.')[-3]][list].append(dnskey)
		for (k,v) in secondleveldns.iteritems():
			print '-----------------------------'
			print "Second Domain Name: %s" % k
			print "Total: %d" % len(v)
			for k1,v1 in v.iteritems():
				print "%s" % k1
				for dns in v1:
					print "%s" % dns
			print '-----------------------------'
								







