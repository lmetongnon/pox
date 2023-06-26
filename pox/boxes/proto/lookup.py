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
    '''
        The implementation of the lookup request where an ip is send and we expect to get the managing box identity.
    '''
    def __init__(self, version=None, raw=None, prev=None, **kwargs):
        packet_base.__init__(self)

        self.prev       = prev
        self.version    = version

        self.userIP     = IP_ANY if self.version in VERSION_MEXP_BOX_IPV4 else IPAddr6.UNDEFINED  # 32 - 128 bits

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

    def __eq__(self, other:"LookupRequest")->bool:
        if not isinstance(other, LookupRequest): return False
        if self.userIP != other.userIP: return False
        return True

    def _to_str(self) -> str:
        return "[LookupRequest User IP:%s]" % (self.userIP)

    def __repr__(self) -> str:
        return self._to_str()

class LookupDelegateRequest(LookupRequest):
    def _to_str(self) -> str:
        return "[LookupDelegateRequest User IP:%s]" % (self.userIP)


# ==============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Port             |            Reserved           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                             BoxIP                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                            Network                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                            Netmask                            |
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
# |                                                               |
# +                                                               +
# |                                                               |
# +                            Network                            +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                            Netmask                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ==============================================================================


class LookupReply(packet_base):
    '''
        The implementation of the reply of a lookup request where your zone box manager send you the identity (IP, port) of the box you need.
    '''
    def __init__(self, version=None, raw=None, prev=None, **kwargs):
        packet_base.__init__(self)

        self.prev       = prev
        self.version    = version

        self.port      = 0     # 16 bits
        self.boxIP     = IP_ANY if self.version in VERSION_MEXP_BOX_IPV4 else IPAddr6("::")  # 32 - 128 bits
        self.network   = IP_ANY if self.version in VERSION_MEXP_BOX_IPV4 else IPAddr6("::")  # x 32 - 128 bits
        self.netmask   = 0  # x 32 bits

        if raw is not None:
            self.parse(raw)

        self._init(kwargs)

    def hdr (self, payload:"packet_base subclass") -> bytes:
        s = struct.pack('!H', self.port)
        s+= b'\000' * 2
        s += self.boxIP.raw
        s += self.network.raw
        s +=  struct.pack('!i', self.netmask)
        return s

    def parse (self, raw:bytes):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw
        (self.port) = struct.unpack('!H', raw[0:2])[0]
        raw = raw[4:]
        if self.version in VERSION_MEXP_BOX_IPV4:
            self.boxIP = IPAddr(raw[:4], networkOrder = False)
            raw = raw[4:]
        elif self.version in VERSION_MEXP_BOX_IPV6:
            self.boxIP = IPAddr6(raw[:16], networkOrder = False)
            raw = raw[16:]
        
        if len(raw) == 8:
            self.network = IPAddr(raw[:4], networkOrder = False)
            raw = raw[4:]
        else:
            self.network = IPAddr6(raw[:16], networkOrder = False)
            raw = raw[16:]
        (self.netmask) = struct.unpack('!i', raw)[0]
        
        self.parsed = True

    def __eq__(self, other:"LookupReply") -> bool:
        if not isinstance(other, LookupReply): return False
        if self.port != other.port: return False
        if self.boxIP != other.boxIP: return False
        if self.network != other.network: return False
        if self.netmask != other.netmask: return False
        return True

    def _to_str(self) -> str:
        return "[LookupReply v(%d) %s/%d => %s:%d]" % (self.version, self.network, self.netmask, self.boxIP, self.port)

    def __repr__(self) -> str:
        return self._to_str()

class LookupDelegateReply(LookupReply):
    def _to_str(self) -> str:
        return "[LookupDelegateReply v(%d) %s/%d => %s:%d]" % (self.version, self.network, self.netmask, self.boxIP, self.port)