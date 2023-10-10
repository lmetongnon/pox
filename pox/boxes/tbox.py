from pox.core import core

from pox.lib.addresses import IPAddr, IPAddr6
from pox.boxes.manager import Tmanager

log = core.getLogger('tbox')

class Tbox(object):

	def __init__(self, ip, port, version, filename):
		self.ip = ip
		self.port = port
		self.messageManager = Tmanager(self, ip, port, version, filename)

# def launch(ip=IPAddr6("2000:db8::1"), port=15700):
def launch(box_ip="2.2.0.1", box_port=15700, version=4, filename=None):
	log.debug("launch %s %s %s %s" % (box_ip, box_port, version, filename))
	Tbox(box_ip, box_port, version, filename)