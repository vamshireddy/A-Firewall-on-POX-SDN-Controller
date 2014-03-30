'''
Coursera:
- Software Defined Networking (SDN) course
-- Module 4 Programming Assignment

Professor: Nick Feamster
Teaching Assistant: Muhammad Shahbaz
'''

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
''' Add your imports here ... '''
from pox.lib.util import str_to_bool
import time
import csv

log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ[ 'HOME' ]  

''' Add your global variables here ... '''



class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")

    def _handle_ConnectionUp (self, event):    
        ''' Add your logic here ... '''
        print "hello"
        log.debug("Connection %s"%(event.connection,))
        self.connection = event.connection
        
        ifile = open(policyFile,"rb")
        reader = csv.reader(ifile)
        
        dpidstr = dpid_to_str(event.connection.dpid)
        
        rownum = 0
        l = []
        for row in reader:
			if rownum == 0:
				continue
			else:
				for col in row:
					l.append(col)
				send_packet(l[0],l[1],l[2],dpidstr)
			l = []
			rownum+=1
		log.debug("Firewall rules installed on %s"%dpidToStr)
    def send_packet(self,sid,src,dest,dpidstr):
	print "Src is ",str(src)
	print "Src is ",str(EthAddr(src))
	match = of.ofp_match()
	msg = of.ofp_flow_mod()
	msg.priority = 32768
	msg.match.dl_src = EthAddr(src)
	msg.match.dl_dst = EthAddr(dest)
	self.connection.send(msg)
	

def launch ():
    '''
    Starting the Firewall module
    '''
    print "Starting firewall!!"
    core.registerNew(Firewall)
