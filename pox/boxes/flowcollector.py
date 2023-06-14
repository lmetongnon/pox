from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.boxes.rbox import Rbox
from pox.boxes.utils.mylist import FlowList

log = core.getLogger('flowcollector')

class FlowCollector(object):

	def __init__(self, stats):

		self.stats = stats
		self.srcFlowList = FlowList()
		self.dstFlowList = FlowList()
		self.box = Rbox.getInstance()
		self.box.flowcollector = self
		self._init()

	def _init(self):
		for flow in self.stats:
			if flow.match.nw_proto in (1, 6, 17) and (flow.match.tp_src is not  None or flow.match.tp_dst is not None):
				self.srcFlowList.updateSet(flow.match.nw_src, flow.match.nw_dst, flow.match.tp_dst)
				self.srcFlowList.updateFlow(flow.match.nw_src, flow.match)
				self.dstFlowList.updateSet(flow.match.nw_dst, flow.match.nw_src, flow.match.tp_src)
				self.dstFlowList.updateFlow(flow.match.nw_dst, flow.match)
				log.debug("_init %s " % (flow.show()))
				self.check()

	def check(self):
		# for flow in self.stats:
		# 	if flow.match.nw_proto in (1, 6, 17) and (flow.match.tp_src is not  None or flow.match.tp_dst is not None):
		# log.debug("check %s " % (flow.show()))
		log.debug("SFlowList check %s " % (self.srcFlowList))
		log.debug("DFlowList check %s " % (self.dstFlowList))