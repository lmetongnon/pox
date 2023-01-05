from pox.lib.addresses import IPAddr, IPAddr6
from pox.boxes.manager import Tmanager

class Tbox(object):

	def __init__(self, ip, port):
		self.ip = ip
		self.port = port
		self.messageManager = Tmanager(self, ip, port)

# def launch(ip=IPAddr6("2000:db8::1"), port=15700):
def launch(ip="192.168.0.1", port=15700):
	Tbox(ip, port)