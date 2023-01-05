import struct
from pox.lib.packet.packet_utils import *

from pox.lib.packet.packet_base import packet_base
from pox.lib.addresses import *
from pox.boxes.proto.mexp import VERSION_MEXP_BOX_IPV4, VERSION_MEXP_BOX_IPV6

    # TCode         = 4
    # UNIQ_ID_CHECK = 0 # Unique Identity Check
    # KEY_INIT      = 1 # Key Initialization 
    # ZONE_RQST     = 2
    # ZONE_RPLY     = 3
    # REGISTRATION_RQST = 4
    # REGISTRATION_RPLY = 5
# ==============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Port             |            Reserved           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ==============================================================================

class ZoneRequest(packet_base):
    def __init__(self, version=None, raw=None, prev=None, **kwargs):
        packet_base.__init__(self)

        self.prev       = prev
        self.version    = 0

        self.port       = 0

        if raw is not None:
            self.parse(raw)

        self._init(kwargs)

    def hdr(self, payload:"packet_base subclass") -> bytes:
        s = struct.pack('!H', self.port)
        s += b'\000' * 2
        return s

    def parse(self, raw:bytes):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw
        (self.port) = struct.unpack('!H', raw[:2])
        self.parsed = True

    def __eq__(self, other:"ZoneRequest") -> bool:
    	if not isinstance(other, ZoneRequest): return False
    	if self.port != other.port : return False
    	return True
    
    def _to_str(self) -> str:
        return "[port:%s]" % (self.port, )

    def __repr__(self) -> str:
        return self._to_str()
# ==============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Port             |            Reserved           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                             BoxIP                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
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

class ZoneReply(packet_base):
    def __init__(self, version=None, raw=None, prev=None, **kwargs):
        packet_base.__init__(self)

        self.prev       = prev
        self.version    = version

        self.port       = 0
        self.boxIP      = None

        if raw is not None:
            self.parse(raw)

        self._init(kwargs)

    def hdr(self, payload:"packet_base subclass") -> bytes:
        s = struct.pack('!H', self.port)
        s += b'\000' * 2
        s += self.boxIP.raw 
        return s

    def parse(self, raw:bytes):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw
        self.port = struct.unpack('!H', raw[0:2])[0]
        if self.version in VERSION_MEXP_BOX_IPV4:
            self.boxIP = IPAddr(raw[4:8], networkOrder=False)
        elif self.version in VERSION_MEXP_BOX_IPV6:
            self.boxIP = IPAddr6(raw[4:20], raw=True) 
        else:
            self.msg("Warning version %u is not manage data len %u" % (self.version, len(raw),))
            return
        
        self.parsed = True

    def __eq__(self, other:"ZoneReply") -> bool:
    	if not isinstance(other, ZoneReply): return False
    	if self.port != other.port: return False
    	if self.boxIP != other.boxIP: return False
    	return True

    def _to_str(self) -> str:
        return "[v:%s, boxIP:%s, port:%s]" % (self.version, self.boxIP, self.port,)
    
    def __repr__(self) -> str:
        return self._to_str()

# =============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Port             |            Reserved           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                            Network                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                            Netmask                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# =============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Port             |            Reserved           |
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
# =============================================================================

class RegistrationRequest(packet_base):
    def __init__(self, version=None, raw=None, prev=None, **kwargs):
        packet_base.__init__(self)

        self.prev       = prev
        self.version    = version

        self.port       = 0         # 16 bits
        self.networks   = []        # x 32 - 128 bits
        self.netmasks   = []        # x 32 bits

        if raw is not None:
            self.parse(raw)

        self._init(kwargs)

    def hdr(self, payload:"packet_base subclass") -> bytes:
        s = struct.pack('!H', self.port)
        s += b'\000' * 2
        for net, mask in zip(self.networks, self.netmasks):
            s += net.raw
            s +=  struct.pack('!i', mask)
        return s

    def parse(self, raw:bytes):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw
        (self.port) = struct.unpack('!H', raw[0:2])[0]
        raw = raw[4:]
        ipLen = 4 if self.version in VERSION_MEXP_BOX_IPV4 else 16

        if len(raw) % 2 != 0:
            self.msg("Warning registration request packet data in incomplete to parse:"
                " data len %u" % (len(raw),))
            return

        while len(raw) >= ipLen + 4:
            try:
                if self.version in VERSION_MEXP_BOX_IPV4:
                    self.networks.append(IPAddr(raw[:ipLen], networkOrder=False))
                elif self.version in VERSION_MEXP_BOX_IPV6 :
                    self.networks.append(IPAddr6(raw[:ipLen], raw=True))
                else:
                    self.msg("Warning version %u is not manage data len %u" % (self.version, len(raw),))
                    return
                
                self.netmasks.append(struct.unpack('!i', raw[ipLen:4+ipLen])[0])

            except Exception as e:
                self.err("Registration Request parsing networks and netmasks" +str(e))
                return None
            raw = raw[ipLen+4:]

        self.msg("ipLen %u, Network %s and netmask %s" % (ipLen, self.networks, self.netmasks))
        if len(raw) != 0:
            self.err("Registration Request had partial parsing %s bytes left" % (len(raw),))

        self.parsed = True

    def __eq__(self, other:"RegistrationRequest") -> bool:
    	if not isinstance(other, RegistrationRequest): return False
    	if self.port != other.port: return False
    	if self.networks != other.networks: return False
    	if self.netmasks != other.netmasks: return False
    	return True

    def _to_str(self):
        return "[port:%s, networks:%s, netmasks:%s]" % (self.port, self.networks, self.netmasks,)

    def __repr__(self):
        return self._to_str()

# ==============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Decision   |                    Reserved                   |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ==============================================================================
class RegistrationReply(packet_base):
    def __init__(self, version=None, raw=None, prev=None, **kwargs):
        packet_base.__init__(self)

        self.prev       = prev
        self.version    = version

        self.decision   = False

        if raw is not None:
            self.parse(raw)

        self._init(kwargs)

    def hdr(self, payload: "packet_base subclass") -> bytes:
        s = struct.pack('!?', self.decision)
        s+= b'\000' * 3
        return s

    def parse(self, raw:bytes):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw

        self.decision = struct.unpack('!?', raw[:1])[0]

        self.parsed = True

    def __eq__(self, other:"RegistrationReply") -> bool:
    	if not isinstance(other, RegistrationReply): return False
    	if self.decision != other.decision: return False
    	return True
    
    def _to_str(self):
        return "[decision:%s]" % (self.decision, )

    def __repr__(self):
        return self._to_str()