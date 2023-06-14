import struct
from pox.lib.packet.packet_utils import *

from pox.lib.packet.packet_base import packet_base
from pox.lib.addresses import *


#  ============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Protocol   |   Alert type  |            Duration           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          Source Port          |        Destination Port       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Source IP                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Destination IP                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# =============================================================================
# 
# 
# 
# =============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Protocol   |   Alert type  |            Duration           |
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
# =============================================================================

class AlertNotification(packet_base):
    '''
        The implementation of the alert notification where the suspiscious flow + the fault + the penality duration are send to its box manager.
    '''
    def __init__(self, version=None, raw=None, prev=None, **kwargs):
        packet_base.__init__(self)
        self.prev           = prev
        self.version        = version

        self.proto          = 0     # 8 bits
        self.alertType      = 0     # 8 bits
        self.duration       = 0     # 16 bits
        self.sport          = 0     # 16 bits
        self.dport          = 0     # 16 bits
        self.sip            = None  # 32 - 128 bits
        self.dip            = None  # 32 - 128 bits

        if raw is not None:
            self.parse(raw)

        self._init(kwargs)

    def hdr (self, payload:"packet_base subclass") -> bytes:
        s = struct.pack('!BBHHH', self.proto, 
                        self.alertType, 
                        self.duration, 
                        self.sport, 
                        self.dport)
        s += self.sip.raw
        s += self.dip.raw
        return s

    def parse(self, raw:bytes):
        assert isinstance(raw, bytes)
        self.raw = raw
        self.size = len(raw)
        (self.proto, self.alertType, self.duration, self.sport, self.dport) = struct.unpack('!BBHHH', raw[:8])
        if self.size == 16 :
            self.sip = IPAddr(raw[8:12], networkOrder = False)
            self.dip = IPAddr(raw[12:16], networkOrder = False)
        elif self.size == 40 :
            self.sip = IPAddr6(raw[8:24], networkOrder = False)
            self.dip = IPAddr6(raw[24:40], networkOrder = False)
        else :
            self.msg("Warning alert notification packet data too short to parse header:"
                " data len %u" % (len(raw),))
            return
        self.parsed = True

    def __eq__(self, other:"AlertNotification")-> bool:
        if not isinstance(other, AlertNotification): return False
        if self.proto != other.proto : return False
        if self.alertType != other.alertType : return False
        if self.duration != other.duration : return False
        if self.sport != other.sport : return False
        if self.dport != other.dport : return False
        if self.sip != other.sip : return False
        if self.dip != other.dip : return False
        return True

    def _to_str(self) -> str:
        return "[AlertNotif %s:[%d] => %s:[%d] -- {%d}:{%d}]" % (self.sip, self.sport, self.dip, self.dport, self.alertType, self.duration)

    def __repr__(self):
        return self._to_str()

AlertAck = None

#==============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Protocol   |   Alert type  |            Duration           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Source IP                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#==============================================================================
#
#
#
#==============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Protocol   |   Alert type  |            Duration           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                           Source IP                           +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# =============================================================================

class AlertBrdc(packet_base):
    '''
        The implementation of the alert broadcast message used to block a unique IP accross internet for a duration (i.e. case of wide scanning)
    '''
    def __init__(self, version=None, raw=None, prev=None, **kwargs):
        packet_base.__init__(self)
        self.prev           = prev
        self.version        = version

        self.proto          = 0     # 8 bits
        self.alertType      = 0     # 8 bits
        self.duration       = 0     # 16 bits
        self.sip            = None  # 32 - 128 bits

        if raw is not None:
            self.parse(raw)

        self._init(kwargs)

    def hdr(self, payload:"packet_base subclass") -> bytes:
        s = struct.pack('!BBH', self.proto, 
                self.alertType, 
                self.duration)
        s += self.sip.raw
        return s

    def parse(self, raw:bytes):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw
        self.size = len(raw)
        (self.proto, self.alertType, self.duration) = struct.unpack('!BBH', raw[:4])
        if self.size == 12 :
            self.sip = IPAddr(raw[4:8], networkOrder = False)
        elif self.size == 36 :
            self.sip = IPAddr6(raw[4:20], networkOrder = False)
        else :
            self.msg("Warning alert broadcast packet data too short to parse:"
                " data len %u" % (len(raw),))
            return
        self.parsed = True

    def __eq__(self, other:"AlertBrdc") -> bool:
        if not isinstance(other, AlertBrdc): return False
        if self.proto != other.proto: return False
        if self.alertType != other.alertType: return False
        if self.duration != other.duration: return False
        if self.sip != other.sip: return False
        return True

    def _to_str(self):
        return "[AlertBrdc [%d]:%s => %d -- %d ]" % (self.proto, self.sip, self,alertType, self.duration)

    def __repr__(self):
        return self._to_str()