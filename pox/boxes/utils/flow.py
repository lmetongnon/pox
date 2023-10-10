import logging
import pox.openflow.libopenflow_01 as of

log = logging.getLogger('flow')

from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ipv6 import ipv6
from pox.lib.packet.udp import udp
from pox.lib.packet.tcp import tcp
from pox.lib.packet.icmp import icmp
from pox.lib.packet.icmpv6 import icmpv6
from pox.lib.util import initHelper

class FlowHeader(object):
	'''
        The ID of a flow contains (protocol, source IP, source port, destination IP, destination port)
    '''
	def __init__(self, **kwargs):
		self.proto = 0
		self.sip = None
		self.sport = 0
		self.dip = None
		self.dport = 0

		self._init(kwargs)
		
	def _init(self, kwargs):
		initHelper(self, kwargs)

	def flip(self) -> "FlowHeader":
		if self.proto == 1:
			if self.sport == self.dport:
				if self.sport != 0:
					return FlowHeader(proto=self.proto, sip=self.dip, sport=self.sport, dip=self.sip, dport=self.dport)
				else:
					return FlowHeader(proto=self.proto, sip=self.dip, sport=8, dip=self.sip, dport=0)
			else :
				return FlowHeader(proto=self.proto, sip=self.dip, sport=0, dip=self.sip, dport=8)
		else: 
			return FlowHeader(proto=self.proto, sip=self.dip, sport=self.dport, dip=self.sip, dport=self.sport)

	def __str__(self):
		return "%d %s:%d => %s:%d" % (self.proto, self.sip, self.sport, self.dip, self.dport)
	
	def __repr__(self):
		return self.__str__()

	def absoluteEqual(self, other):
		if not isinstance(other, FlowHeader): return False
		return self.__eq__(other) or self.flip().__eq__(other)
	
	def toTuple(self, ip):
		"""
		This function returns the tuple of Ip in the flowheader (sip, dip) with always first member of the tuple the given ip in the parameter, we add the port
		"""
		return (self.sip, self.dip), self.sport if ip == self.sip else (self.dip, self.sip), self.dport
	
	def __eq__(self, other):
		if not isinstance(other, FlowHeader): return False
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

	@staticmethod
	def fromPacket(packet):
		if isinstance(packet, ipv4) or isinstance(packet, ipv6):
			if isinstance(packet.next, udp) or isinstance(packet.next, tcp):
				return FlowHeader(proto=packet.protocol, sip=packet.srcip, dip=packet.dstip, sport=packet.next.srcport, dport=packet.next.dstport)
			elif isinstance(packet.next, icmp) or isinstance(packet.next, icmpv6):
				return FlowHeader(proto=packet.protocol, sip=packet.srcip, dip=packet.dstip, sport=packet.next.type, dport=packet.next.code)

	@staticmethod
	def fromMatch(match):
		if not isinstance(match, of.ofp_match):
			return None
		return FlowHeader(proto=match.nw_proto, sip=match.nw_src, dip=match.nw_dst, sport=match.tp_src, dport=match.tp_dst)

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
		return FlowHeader.__eq__(self, other)

