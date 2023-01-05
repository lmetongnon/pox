import logging
lg = logging.getLogger('flow')

from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ipv6 import ipv6
from pox.lib.packet.udp import udp
from pox.lib.packet.tcp import tcp
from pox.lib.packet.icmp import icmp
from pox.lib.packet.icmpv6 import icmpv6
from pox.lib.util import initHelper

class FlowHeader(object):
	def __init__(self, **kwargs):
		self.proto = 0
		self.sip = None
		self.sport = 0
		self.dip = None
		self.dport = 0

		self._init(kwargs)
		
	def _init(self, kwargs):
		initHelper(self, kwargs)

	def flip(self):
		if self.proto == 1:
			if self.sport == self.dport:
				return FlowHeader(proto=self.proto, sip=self.dip, sport=8, dip=self.sip, dport=0)
			else :
				return FlowHeader(proto=self.proto, sip=self.dip, sport=0, dip=self.sip, dport=8)
		else: 
			FlowHeader(proto=self.proto, sip=self.dip, sport=self.dport, dip=self.sip, dport=self.sport)

	
	def __str__(self):
		return "%s %s[%d] => %s[%d]" % (self.proto, self.sip, self.sport, self.dip, self.dport)
	
	def __eq__(self, other):
		if not isinstance(other. FlowHeader): return False
		if self.proto != other.proto : return False
		if self.sip != other.sip : return False
		if self.sport != other.sport : return False
		if self.dip != other.dip : return False
		if self.dport != other.dport : return False
		return True

	def __ne__(self, other):
		return not self == other 

	def __hash__(self):
		return (self.proto, self.sip, self.sport, self.dip, self.dport).__hash__()

def getFlowheader(packet):
	if isinstance(packet, ipv4) or isinstance(packet, ipv6):
		if isinstance(packet.next, udp) or isinstance(packet.next, tcp):
			return FlowHeader(proto=packet.protocol, sip=packet.srcip, dip=packet.dstip, sport=packet.next.srcport, dport=packet.next.dstport)
		elif isinstance(packet.next, icmp) or isinstance(packet.next, icmpv6):
			return FlowHeader(proto=packet.protocol, sip=packet.srcip, dip=packet.dstip, sport=packet.next.type, dport=packet.next.code)

class Flow(FlowHeader):
	def __init__(self, **kwargs):
		FlowHeader.__init__(self)
		self.packetCount 	= 0
		self.byteCount 		= 0
		self.flowSize 		= 0
		self.duration 		= 0

		self._init(kwargs)

	def __eq__(self, other):
		if not isinstance(other, Flow): return False
		# if FlowHeader.__ne__(other.FlowHeader)
		if self.packetCount != other.packetCount: return False
		if self.byteCount != other.byteCount: return False
		if self.flowSize != other.flowSize : return False
		if self.duration != other.duration : return False
		FlowHeader.__eq__(self, other)

