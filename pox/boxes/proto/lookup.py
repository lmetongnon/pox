from pox.lib.packet.packet_utils import *

from pox.lib.packet.packet_base import packet_base
from pox.lib.addresses import *
from pox.boxes.proto.mexp import VERSION_MEXP_BOX_IPV4, VERSION_MEXP_BOX_IPV6

# ==============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                            User IP                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ==============================================================================
# 
# 
# ==============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                            User IP                            +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ==============================================================================
class LookupRequest(packet_base):
    def __init__(self, version=None, raw=None, prev=None, **kwargs):
        packet_base.__init__(self)

        self.prev       = prev
        self.version    = version

        self.userIP     = None  # 32 - 128 bits

        if raw is not None:
            self.parse(raw)

        self._init(kwargs)

    def hdr (self, payload:"packet_base subclass") -> bytes:
        return self.userIP.raw

    def parse (self, raw:bytes):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw
        size = len(raw)
        if self.version in VERSION_MEXP_BOX_IPV4:
            self.userIP = IPAddr(raw, networkOrder = False)
        elif self.version in VERSION_MEXP_BOX_IPV6 :
            self.userIP = IPAddr6(raw, networkOrder = False)
        
        self.parsed = True

    def __eq__(self, other:LookupRequest)->bool:
        if not isinstance(other, LookupRequest): return False
        if self.userIP != other.userIP: return False
        return True

    def _to_str(self) -> str:
        return "[LookupRequest User IP:%s]" % (self.userIP)

    def __repr__(self) -> rtr:
        return self._to_str()

LookupDelegateRequest = LookupRequest

# ==============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Port             |            Reserved           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                             BoxIP                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ==============================================================================


# ==============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Port             |            Reserved           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                             BoxIP                             +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ==============================================================================


LookupReply(packet_base):
    def __init__(self, version=None, raw=None, prev=None, **kwargs):
        packet_base.__init__(self)

        self.prev       = prev
        self.version    = version

        self.port       = 0 # 16 bits
        self.boxIP      = None # 32 - 128 bits

        if raw is not None:
            self.parse(raw)

        self._init(kwargs)

    def hdr (self, payload:"packet_base subclass") -> bytes:
        s = struct.pack('!H', self.port)
        s+= b'\000' * 2
        s += boxIP.raw
        return s

    def parse (self, raw:bytes):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw
        (self.port) = struct.unpack('!H', raw[0:2])
        raw = raw[4:]
        size = len(raw)
        if self.version in VERSION_MEXP_BOX_IPV4:
            self.boxIP = IPAddr(raw, networkOrder = False)
        elif self.version in VERSION_MEXP_BOX_IPV6:
            self.boxIP = IPAddr6(raw, networkOrder = False)
        
        self.parsed = True

    def __eq__(self, other:LookupReply) -> bool:
        if not isinstance(other, LookupReply): return False
        if self.port != other.port: return False
        if self.boxIP != other.boxIP: return False
        return True

    def _to_str(self):
        return "[LookupReply %d => %s:%d]" % (self.version, self.boxIP, self.port)

    def __repr__(self):
        return self._to_str()

LookupDelegateReply=LookupReply