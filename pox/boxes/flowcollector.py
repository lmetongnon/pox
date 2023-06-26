from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.boxes.rbox import Rbox
from pox.boxes.utils.mylist import FlowList

import time, copy

log = core.getLogger('flowcollector')

class FlowCollector(object):

	def __init__(self, stats):
		# log.debug("__init__ %s " % (str(stats)))
		self.stats = stats
		self.srcFlowList = FlowList()
		self.dstFlowList = FlowList()
		self.box = Rbox.getInstance()
		self.box.flowcollector = self
		self._init()
		self._updateFlow()

	def _updateFlow(self):
		if self.box.flowList.timeout != -1 and time.time() > self.box.flowList.timestamp + self.box.flowList.timeout:
			self.box.flowList.__init__()
			for key in self.srcFlowList.ipSet.keys():
				if self.box.isOurDevice(key):
					continue
				self.box.flowList.ipSet[key] = copy.deepcopy(self.srcFlowList.ipSet[key])

			for key in self.srcFlowList.ipFlows.keys():
				if self.box.isOurDevice(key):
					continue
				self.box.flowList.ipFlows[key] = copy.deepcopy(self.srcFlowList.ipFlows[key])
		else:
			for key in self.srcFlowList.ipSet.keys():
				if self.box.isOurDevice(key):
					continue
				if key in self.box.flowList.ipSet.keys():
					self.box.flowList.ipSet[key].update(self.srcFlowList.ipSet[key])
				else:
					self.box.flowList.ipSet[key] = copy.deepcopy(self.srcFlowList.ipSet[key])

			for key in self.srcFlowList.ipFlows.keys():
				if self.box.isOurDevice(key):
					continue
				if key in self.box.flowList.ipFlows.keys():
					self.box.flowList.ipFlows[key].update(self.srcFlowList.ipFlows[key])
				else:
					self.box.flowList.ipFlows[key] = copy.deepcopy(self.srcFlowList.ipFlows[key])

	def _init(self):
		for flow in self.stats:
			if flow.match.nw_proto in (1, 6, 17) and (flow.match.tp_src is not  None or flow.match.tp_dst is not None):
				self.srcFlowList.updateSet(flow.match.nw_src, flow.match.nw_dst, flow.match.tp_dst)
				self.srcFlowList.updateFlow(flow.match.nw_src, flow.match)
				self.dstFlowList.updateSet(flow.match.nw_dst, flow.match.nw_src, flow.match.tp_src)
				self.dstFlowList.updateFlow(flow.match.nw_dst, flow.match)
		self.check()

	def check(self):
		for ip in self.dstFlowList.ipFlows.keys():
			if self.rbox.isOurDevice(ip):
				continue
			maliciousFlow = self.rbox.detection.dosDetection(ip, dstFlowList[ip])
			if maliciousFlow is not None:
				self.rbox.alertList.add(ip, Alert(Alert.DOS, maliciousFlow))
			maliciousFlow = self.rbox.detection.ddosDetection(ip, dstFlowList[ip])
			if maliciousFlow is not None:
				self.rbox.alertList.add(ip, Alert(Alert.DDOS, maliciousFlow))
		# log.debug("SFlowList check %s " % (self.srcFlowList))
		# log.debug("DFlowList check %s " % (self.dstFlowList))