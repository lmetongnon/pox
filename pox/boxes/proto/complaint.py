import struct
from pox.lib.packet.packet_utils import *

from pox.lib.packet.packet_base import packet_base
from pox.lib.addresses import *

# 1. The complaint request sent by a RearBox to its ZoneBox with the
# the IP address of the RearBox perpetrator and a proof of the
# wrongdoing.
# 2. The complaint inquiry sent to the RearBox accused of misuse to
# request a proof of innocence.
# 3. The complaint reply contains the acknowledgement of the
# ZoneBox to the RearBox complaining.
# 4. The complaint mitigation is a message sent to the ZoneBox of
# the malicious RearBox or a third party, i.e. an ISP or a another
# network manager organization to mitigate the attack.

# 4 COMPLAINT
# I didn't accept the traffic send the permission denied
# The traffic should have stop, send the permission request so we can check the duration
# The traffic was report so you should have stop it, send the alert message
# The permission was never asked, send the traffic packet

# ==============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                             BoxIP                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ==============================================================================


# ==============================================================================
#  0                   1                   2                   3  
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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

class ComplaintRequest(packet_base):
    '''
        The implementation of complaint request where a box is suspect another one is compromised or not working properly. The box send the control message as proof
    '''
    def __init__(self, version=None, raw=None, prev=None, **kwargs):
        packet_base.__init__(self)

        self.prev           = prev
        self.version        = version

        self.boxIP          = None  # 32 - 128 bits
        
        self.next           = b''

        if raw is not None:
            self.parse(raw)

        self._init(kwargs)

    def hdr (self, payload:"packet_base subclass") -> bytes:
        assert isinstance(payload, bytes)
        return boxIP.raw

    def parse(self, raw:bytes):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw

        if self.version in VERSION_MEXP_BOX_IPV4 :
            self.boxIP = IPAddr(raw[:4], networkOrder=False)
            raw = raw[4:]
        elif self.version in VERSION_MEXP_BOX_IPV6 :
            self.boxIP = IPAddr6(raw[:16], raw=True)
            raw = raw[16:]
        else:
            self.msg("Warning version is not manage data len %u" % (len(raw),))
            return

        self.parsed = True

        self.next = ControlNotification(prev=this, raw=raw)

    def __eq__(self, other:ComplaintRequest) -> bool:
        if not isinstance(other, ComplaintRequest): return False
        if self.boxIP != other.boxIP: return False
        if self.payload != other.payload: return False
        return True

    def _to_str(self):
        return "[ComplaintRequest %s:{%s} ]" % (self.boxIP, self.payload)

    def __repr__(self):
        return self._to_str()

class ComplaintInquiry(packet_base):
    '''
        The implementation of the inquiry from the zone box manager where it question the suspect box to have the other side of the story (i.e. we can be in a man in the middle case)
    '''
    def __init__(self, version=None, raw=None, prev=None, **kwargs):
        packet_base.__init__(self)

        self.prev           = prev
        self.version        = version

        self.boxIP          = None  # 32 - 128 bits
        
        self.next           = b''

        if raw is not None:
            self.parse(raw)

        self._init(kwargs)

    def hdr (self, payload:"packet_base subclass") -> bytes:
        assert isinstance(payload, bytes)
        return boxIP.raw

    def parse(self, raw:bytes):
        assert isinstance(raw, bytes)
        self.next = None # In case of unfinished parsing
        self.raw = raw

        if self.version in VERSION_MEXP_BOX_IPV4 :
            self.boxIP = IPAddr(raw[:4], networkOrder=False)
            raw = raw[4:]
        elif self.version in VERSION_MEXP_BOX_IPV6 :
            self.boxIP = IPAddr6(raw[:16], raw=True)
            raw = raw[16:]
        else:
            self.msg("Warning version is not manage data len %u" % (len(raw),))
            return

        self.parsed = True

        self.next = Mexp(prev=this, raw=raw)

    def __eq__(self, other:ComplaintInquiry) -> bool:
        if not isinstance(other, ComplaintInquiry): return False
        if self.boxIP != other.boxIP: return False
        if self.payload != other.payload: return False
        return True

    def _to_str(self):
        return "[ComplaintInquiry %s:{%s} ]" % (self.boxIP, self.payload)

    def __repr__(self):
        return self._to_str()

class ComplaintReply(packet_base):
    '''
        The implementation of the reply of a complaint request where the zone box manager come to a decision after its investigation..
    '''
    def __init__(self, version=None, raw=None, prev=None **kwargs):
        packet_base.__init__(self)
        
        self.prev           = prev
        self.version        = version

        self.boxIP          = None  # 32 - 128 bits
        self.next           = b''


        if raw is not None:
            self.parse(raw)

class ComplaintMitigation(packet_base):
    '''
        The implementation of the mitigation to deploy following the investigation. This is send to the suspicious box or its zone box manager to stop the malicious activity.
    '''
    def __init__(self, version=None, raw=None, prev=None, **kwargs):
        packet_base.__init__(self)