################################################
#    test.py
#
#    One Line Description
#
#    Copyright (c) 2006-2014 Hillstone Networks, Inc.
#
#    PROPRIETARY RIGHTS of Hillstone Networks are
# involved in the subject matter of this material.
# All manufacturing, reproduction, use and sales rights 
# pertaining to this subject matter are overned by the license agreement.
# The recipient of this software implicitly accepts the terms of the license.
#
#    Creation Date: 2014-05-17
#    Author: wtao
#
#    $ID$
#
################################################

#!/usr/bin/python

from scapy.all import *
import sys

if __name__ == '__main__':
	object = rdpcap(sys.argv[1])
	for eachpacket in object:
		print eachpacket.show()
