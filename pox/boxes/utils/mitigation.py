import logging
lg = logging.getLogger('mitigation')

import threading
import time

from pox.lib.addresses import IPAddr, IPAddr6
from pox.boxes.proto.mexp import Mexp
from pox.boxes.utils.mylist import BoxList

class AbstractMitigation(object):
	def __init__(self, box):
		self.box = box

	def process(self, data):
		raise NotImplementedError("process() not implemented")

class Mitigation(AbstractMitigation):
	def __init__(self, box):
		AbstractMitigation.__init__(self, box)

	def process(self, data):
		switcher = {
			COMPLIANCE: self.mitigationCompliance,
			SCAN: self.mitigationScan,
			DOS: self.mitigationDos,
			DDOS: self.mitigationDdos
		}
		alert = data[1]
		func = switcher.get(alert.alertType)
		if func is not None:
			func(data)
	
	def mitigationScan(self, data):
		raise NotImplementedError("process() not implemented")
	
	def mitigationDos(self, data):
		raise NotImplementedError("process() not implemented")
	
	def mitigationDdos(self, data):
		raise NotImplementedError("process() not implemented")