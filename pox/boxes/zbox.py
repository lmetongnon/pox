from pox.core import core

from pox.lib.addresses import IPAddr, IPAddr6
from pox.boxes.manager import Zmanager 

log = core.getLogger('zbox')

class Zbox(object):
	def __init__(self, ip, port, networks):
		log.debug("__init__ ip=%s, port=%s, networks=%s" % (ip, port, networks,))

		# The box IP address
		self.ip = ip

		self.networks = set()		
		if not isinstance(networks, list):
			networks = [networks]
		
		if networks[0].find(':') != -1 :
			for net in networks:
				self.networks.add(IPAddr6.parse_cidr(net))
		else :
			for net in networks:
				self.networks.add(IPAddr.parse_cidr(net))

		# The box message manager
		self.messageManager = Zmanager(self, ip, port)

# def launch (ip=IPAddr6("2000:db8:1::1"), port=15000, networks=[IPAddr6.parse_cidr("2000:db8::/32")]):
def launch (ip="10.0.0.100", port=15000, networks=["10.0.0.0/8"]):
	pass
	log.debug("launch %s %s %s" % (ip, port, networks))
	Zbox(ip, port, networks)
