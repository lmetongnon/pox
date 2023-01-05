#==============================================================================
#                                                                              
#						MExP Header Format   
#						  
#							IPv4 Box	                                    
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version|  Code |     TCode     | Message Length|  Next Header  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Message Identifier                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                             Box IP                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                            Payload                            +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# 
#                               IPv6 Box                              
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version|  Code |     TCode     | Message Length|  Next Header  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Message Identifier                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                             Box IP                            +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                            Payload                            +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# =============================================================================

"""
The mitigation exchange protocol
"""
import time
from pox.lib.packet.packet_utils import *
from pox.lib.packet.packet_base import packet_base
from pox.lib.addresses import IPAddr, IPAddr6

""" 
TCode
"""
# INIT          = 0
SYNC			= 0
ALERT 			= 1
COMPLAINT 		= 2
LOOKUP 			= 3
ACTIVATION		= 4
PERMISSION 		= 5
POLICY 			= 6
FLOW 			= 7

"""
Code
"""
# TCode 		= 0
ACK 			= 0
MESSAGE_ERR		= 1

# TCode			= 1
ALERT_NOTIF		= 0
ALERT_ACK		= 1
ALERT_BRDT		= 2

# TCode			= 2
CONTROL_NOTIF	= 0
CONTROL_ACK		= 1

# TCode			= 3
LOOKUP_RQST		= 0
LOOKUP_RPLY		= 1
LOOKUP_DL_RQST	= 2
LOOKUP_DL_RPLY	= 3

# TCode 		= 4
UNIQ_ID_CHECK	= 0 # Unique Identity Check
KEY_INIT 		= 1 # Key Initialization 
ZONE_RQST		= 2
ZONE_RPLY		= 3
REG_RQST 		= 4
REG_RPLY 		= 5

# TCode			= 5
PERMISSION_RQST	= 1
PERMISSION_RPLY	= 2

# TCode 		= 6
POLICY_UPDATE	= 0
POLICY_DEAC		= 1
POLICY_PERST	= 2
POLICY_DEFAULT	= 3

# TCode 		= 7
FLOW_RQST 		= 0
FLOW_RPLY 		= 1

# TCode 		= 8
COMPLAINT_RQST	= 0
COMPLAINT_INQ	= 1
COMPLAINT_RPLY	= 2
COMPLAINT_MITI	= 3

PSH_ADDR      = 14

VERSION_MEXP_BOX_IPV4 = (1, 3)
VERSION_MEXP_BOX_IPV6 = (2, 4)

class Mexp(packet_base):

	MIN_LEN = 12
	NO_NEXT_HEADER = 56

	def __init__(self, raw=None, prev=None, **kwargs):
		packet_base.__init__(self)
		self.msg(kwargs)
		self.prev 			= prev

		self.version 		= 0 					# 4 bits -- protocol version
		self.tcode			= 0 					# 4 bits -- tcode number
		self.code 			= 0						# 8 bits -- code number
		self.packetLength 	= 0 					# 8 bits
		self.nextHeader 	= self.NO_NEXT_HEADER 	# 8 bits
		self.mid 			= int(time.time())		# 32 bits
		self._boxIP 		= None 					# 32 or 128 bits
		self.hdrLength		= 0

		self.next = b''

		if raw is not None:
			self.parse(raw)

		self._init(kwargs)

	def hdr(self, payload:"packet_base subclass") -> bytes:
		assert isinstance(payload, bytes)
		self.packetLength = self.hdrLength + len(payload)

		vtc = self.version << 4
		vtc |= (self.code & 0xff)
		s = struct.pack('!BBBBI', vtc,
							self.tcode, 
							self.packetLength, 
							self.nextHeader,
							self.mid)
		
		assert (self.boxIP is not None)
		s += self.boxIP.raw

		return s

	@property
	def boxIP(self):
		return self._boxIP
		
	@boxIP.setter
	def boxIP(self, boxIP):
		if boxIP is not None:
			self._boxIP 	= boxIP
			self.hdrLength 	= 24 if len(self.boxIP) == 16 else 12

	def parse(self, raw:bytes):
		assert isinstance(raw, bytes)
		self.next = None # In case of unfinished parsing
		self.raw = raw
		if len(raw) < self.MIN_LEN:
			self.msg("Warning MExP packet data too short to parse header:"
				" data len %u" % (len(raw),))
			return

		(vtc, self.tcode, self.packetLength, nh, self.mid) = struct.unpack('!BBBBI', raw[:8])
		
		self.version = vtc >> 4
		self.code = vtc & 0x0f
		self.nextHeader = nh

		if self.version not in VERSION_MEXP_BOX_IPV4 and self.version not in VERSION_MEXP_BOX_IPV6:
			self.msg ("Wrong version number &u", self.version)

		if self.version in VERSION_MEXP_BOX_IPV4:
			self.boxIP = IPAddr(raw[8:12])
			self.hdrLength = 12
		elif self.version in VERSION_MEXP_BOX_IPV6:
			self.boxIP = IPAddr6(raw[8:24], raw=True)
			self.hdrLength = 24

		# TODO : Need to support IPv4 and IPv6 header or TLS
		while nh != self.NO_NEXT_HEADER:
			pass

		# Message without content
		if nh == self.NO_NEXT_HEADER:
			self.next = None

		self.parsed = True

		if self.packetLength > len(raw):
			self.msg("Warning MExP packet data incomplete (%s of %s)"
					 % (len(raw), self.packetLength))
		self.next = raw [self.hdrLength:]

		self.parsePayload(self.version)

	def __eq__(self, other) -> bool:
		if not isinstance(other, Mexp): return False
		if self.version != other.version: return False
		if self.tcode != other.tcode: return False
		if self.code != other.code: return False
		if self.packetLength != other.packetLength: return False
		if self.nextHeader != other.nextHeader: return False
		if self.mid != other.mid: return False
		if self.boxIP != other.boxIP: return False
		if self.payload != other.payload: return False
		return True

	def _to_str(self) -> bool:
		return "[v:%d mid:%d tc:%d c:%d pl:%d boxIP:%s payload:%s]" % (self.version, self.mid, self.tcode, self.code, self.packetLength, self.boxIP, self.payload)

	def __repr__(self):
		return self._to_str()

	def parsePayload(self, version:int):
		# parse payload
		switcher = {
			SYNC : self.parseSync,
			ALERT: self.parseAlert,
			COMPLAINT: self.parseComplaint,
			LOOKUP:	self.parseLookup,
			ACTIVATION:	self.parseActivation,
			PERMISSION:	self.parsePermission,
			POLICY:	self.parsePolicy,
			FLOW: self.parseFlow
		}
		func = switcher.get(self.tcode)
		if func is None:
			self.next = None
		else:
			func(version)

	def	parseFlow(self, version:int):
		raise NotImplementedError("parseFlow not implemented")

	def	parseLookup(self, version:int):
		from pox.boxes.proto.lookup import LookupRequest, LookupReply, LookupDelegateRequest, LookupDelegateReply
		switcher = {
			LOOKUP_RQST: LookupRequest,
			LOOKUP_RPLY: LookupReply,
			LOOKUP_DL_RQST: LookupDelegateRequest,
			LOOKUP_DL_RPLY: LookupDelegateReply
		}
		func = switcher.get(self.code)
		self.next = func(version=version, raw=self.next, prev=self)
		
	def	parsePolicy(self, version:int):
		raise NotImplementedError("parsePolicy not implemented")

	def	parseSync(self, version:int):
		raise NotImplementedError("parseSync not implemented")

	def parseActivation(self, version:int):
		# self.msg("parseActivation %s" % self)
		from pox.boxes.proto.activation import ZoneRequest, ZoneReply, RegistrationRequest, RegistrationReply
		switcher = {
			UNIQ_ID_CHECK: None,
			KEY_INIT: None,
			ZONE_RQST: ZoneRequest,
			ZONE_RPLY: ZoneReply,
			REG_RQST: RegistrationRequest,
			REG_RPLY: RegistrationReply
		}
		func = switcher.get(self.code)
		self.next = func(version=version, raw=self.next, prev=self)

	def parseAlert(self, version:int):
		from pox.boxes.proto.alert import AlertNotification, AlertBrdc, AlertAck
		switcher= {
			ALERT_NOTIF: AlertNotif,
			ALERT_BRDT: AlertBrdc,
			ALERT_ACK: AlertAck
		}
		func = switcher.get(self.code)
		self.next = func(version=version, raw=self.next, prev=self)

	def parseComplaint(self, version:int):
		from pox.boxes.proto.complaint import ComplaintInquiry, ComplaintRequest, ComplaintReply, ComplaintMitigation
		switcher = {
			COMPLAINT_INQ: ComplaintInquiry,
			COMPLAINT_RQST: ComplaintRequest,
			COMPLAINT_RPLY: ComplaintReply,
			COMPLAINT_MITI: ComplaintInquiry
		}
		func = switcher.get(self.code)
		self.next = func(version=version, raw=self.next, prev=self)

	def parsePermission(self, version:int):
		from pox.boxes.proto.permission import PermissionRequest, PermissionReply
		switcher = {
			PERMISSION_RQST: PermissionRequest,
			PERMISSION_RPLY: PermissionReply
		}
		func = switcher.get(self.code)
		self.next = func(version=version, raw=self.next, prev=self)
