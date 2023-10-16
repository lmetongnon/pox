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
		self._updateBoxFlow()

	def _updateBoxFlow(self):
		log.debug("_updateBoxFlow")
		if self.box.flowList.timeout != -1 or time.time() > self.box.flowList.timestamp + self.box.flowList.timeout:
			self.box.flowList.__init__()
			for key in self.srcFlowList.ipSet.keys():
				self.box.flowList.ipSet[key] = copy.deepcopy(self.srcFlowList.ipSet[key])

			for key in self.srcFlowList.ipFlows.keys():
				self.box.flowList.ipFlows[key] = copy.deepcopy(self.srcFlowList.ipFlows[key])
		else:
			for key in self.srcFlowList.ipSet.keys():
				if key in self.box.flowList.ipSet.keys():
					self.box.flowList.ipSet[key].update(self.srcFlowList.ipSet[key])
				else:
					self.box.flowList.ipSet[key] = copy.deepcopy(self.srcFlowList.ipSet[key])

			for key in self.srcFlowList.ipFlows.keys():
				if key in self.box.flowList.ipFlows.keys():
					self.box.flowList.ipFlows[key].update(self.srcFlowList.ipFlows[key])
				else:
					self.box.flowList.ipFlows[key] = copy.deepcopy(self.srcFlowList.ipFlows[key])
		log.debug("_updateBoxFlow after: %s", self)

	def _init(self):
		for flow in self.stats:
			if flow.match.nw_proto in (1, 6, 17) and (flow.match.tp_src is not  None or flow.match.tp_dst is not None):
				self.srcFlowList.updateSet(flow.match.nw_src, flow.match.nw_dst, flow.match.tp_dst)
				self.srcFlowList.updateFlow(flow.match.nw_src, flow)
				self.dstFlowList.updateSet(flow.match.nw_dst, flow.match.nw_src, flow.match.tp_src)
				self.dstFlowList.updateFlow(flow.match.nw_dst, flow)
		# log.debug("_init srcFlowList Flow: %s, dstFlowList Flow: %s" % (self.srcFlowList, self.dstFlowList))
		self.check()

	def check(self):
		self.box.detection.process(self.dstFlowList)