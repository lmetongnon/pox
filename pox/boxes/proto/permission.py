import struct
import math
from pox.lib.packet.packet_utils import *

from pox.lib.packet.packet_base import packet_base
from pox.lib.addresses import *
from pox.boxes.proto.mexp import VERSION_MEXP_BOX_IPV4, VERSION_MEXP_BOX_IPV6

# ==============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Protocol   |Max Packet Size|            Duration           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          Source Port          |        Destination Port       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Source IP                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Destination IP                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ==============================================================================
# 
# 
# 
# ==============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Protocol   |Max Packet Size|            Duration           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          Source Port          |        Destination Port       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                           Source IP                           +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                         Destination IP                        +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ==============================================================================

class PermissionRequest(packet_base):
    def __init__(self, version=None, raw=None, prev=None, **kwargs):
        packet_base.__init__(self)

        self.prev           = prev
        self.version        = version

        self.proto          = 0     # 8 bits
        self._maxPacketSize = 188   # 8 bits (1500)
        self.duration       = 0     # 16 bits
        self.sport          = 0     # 16 bits
        self.dport          = 0     # 16 bits
        self.sip            = None  # 32 - 128 bits
        self.dip            = None  # 32 - 128 bits

        if raw is not None:
            self.parse(raw)

        self._init(kwargs)

    @property
    def maxPacketSize(self):
        return self._maxPacketSize * 8
        
    @maxPacketSize.setter
    def maxPacketSize(self, maxPacketSize):
        self._maxPacketSize = math.ceil(maxPacketSize/8)
    
    def hdr (self, payload:"packet_base subclass") -> bytes:
        s = struct.pack('!BBHHH', self.proto, 
                        self._maxPacketSize,
                        self.duration,
                        self.sport,
                        self.dport)
        s += self.sip.raw
        s += self.dip.raw
        return s

    def parse (self, raw:bytes):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw
        (self.proto, self._maxPacketSize, self.duration, self.sport, self.dport) = struct.unpack('!BBHHH', raw[:8])
        if self.version in VERSION_MEXP_BOX_IPV4 :
            self.sip = IPAddr(raw[8:12], networkOrder = False)
            self.dip = IPAddr(raw[12:16], networkOrder = False)
        elif self.version in VERSION_MEXP_BOX_IPV6 :
            self.sip = IPAddr6(raw[8:24], networkOrder = False)
            self.dip = IPAddr6(raw[24:40], networkOrder = False)
        else :
            self.msg("Warning version is not manage data len %u" % (len(raw),))
            return

        self.parsed = True

    def __eq__(self, other:"PermissionRequest") -> bool:
        if not isinstance(other, PermissionRequest): return False
        if self.proto != other.proto: return False
        if self._maxPacketSize != other._maxPacketSize: return False
        if self.duration != other.duration: return False
        if self.sport != other.sport: return False
        if self.dport != other.dport: return False
        if self.sip != other.sip: return False
        if self.dip != other.dip: return False
        return True
    
    def _to_str(self):
        return "[PermissionRequest: %s:[%u] => %s:[%u] -- %u:%u]" % (self.sip, self.sport, self.dip, self.dport, self.duration, self.maxPacketSize)

    def __repr__(self):
        return self._to_str()

# ==============================================================================
# 
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Protocol   |Max Packet Size|            Duration           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          Source Port          |        Destination Port       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Decision   |                    Reserved                   |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Source IP                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Destination IP                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ==============================================================================

class PermissionReply(packet_base):
    def __init__(self, version=None, raw=None, prev=None, **kwargs):
        packet_base.__init__(self)

        self.prev               = prev
        self.version            = version

        self.proto          = 0     # 8 bits
        self._maxPacketSize = 188   # 8 bits (1500)
        self.duration       = 0     # 16 bits
        self.sport          = 0     # 16 bits
        self.dport          = 0     # 16 bits
        self.decision       = False # 8 bits 
        self.sip            = None  # 32 - 128 bits
        self.dip            = None  # 32 - 128 bits



        if raw is not None:
            self.parse(raw)

        self._init(kwargs)

    @property
    def maxPacketSize(self):
        return self._maxPacketSize * 8
        
    @maxPacketSize.setter
    def maxPacketSize(self, maxPacketSize:int):
        self._maxPacketSize = math.ceil(maxPacketSize/8)

    def hdr (self, payload:"packet_base subclass") -> bytes:

        s = struct.pack('!BBHHH?', self.proto, 
                        self._maxPacketSize,
                        self.duration,
                        self.sport,
                        self.dport,
                        self.decision)
        s += b'\000' * 3
        s += self.sip.raw
        s += self.dip.raw
        return s

    def parse (self, raw:bytes):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw
        (self.proto, self._maxPacketSize, self.duration, self.sport, self.dport, self.decision) = struct.unpack('!BBHHH?', raw[:9])
        ipLen = 4 if self.version in VERSION_MEXP_BOX_IPV4 else 16
        raw = raw[12:]
        if self.version in VERSION_MEXP_BOX_IPV4 :
            self.sip = IPAddr(raw[:ipLen], networkOrder = False)
            self.dip = IPAddr(raw[ipLen:ipLen*2], networkOrder = False)
        elif self.version in VERSION_MEXP_BOX_IPV6 :
            self.sip = IPAddr6(raw[:ipLen], networkOrder = False)
            self.dip = IPAddr6(raw[ipLen:ipLen*2], networkOrder = False)
        else :
            self.msg("Warning version is not manage data len %u" % (len(raw),))
            return
        self.parsed = True

    def __eq__(self, other:"PermissionReply") -> bool:
        if not isinstance(other, PermissionReply): return False
        if self.proto != other.proto: return False
        if self._maxPacketSize != other._maxPacketSize: return False
        if self.duration != other.duration: return False
        if self.sport != other.sport: return False
        if self.dport != other.dport: return False
        if self.sip != other.sip: return False
        if self.dip != other.dip: return False
        if self.decision != other.decision: return False
        return True

    def _to_str(self) -> str:
        return "[PermissionReply: %s:[%u] => %s:[%u] -- %u:%u decision %s]" % (self.sip, self.sport, self.dip, self.dport, self.duration, self.maxPacketSize, self.decision)

    def __repr__(self) -> str:
        return self._to_str()