#!/usr/bin/python

import os
import sys
import filter_dns
from scapy.all import *

def dns_statics(object):
	''' '''
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
					if temp not in dnslist[values.qd.qname]:
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

if __name__ == '__main__':
	if os.path.isfile(sys.argv[1]):
		object = rdpcap(sys.argv[1])
		dns = dns_statics(filter_dns.FilterDns(object))
		for (k,v) in dns.iteritems():
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
	else:
		filelist = os.listdir(sys.argv[1])
		for list in filelist:
			print '%s' % list
			object = rdpcap(os.path.abspath(sys.argv[1]+ '/' + list))
			dns = dns_statics(filter_dns.FilterDns(object))
			for (k,v) in dns.iteritems():
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


