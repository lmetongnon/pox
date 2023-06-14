import logging
import pox.openflow.libopenflow_01 as of

from pox.boxes.utils.tools import Permission
from pox.boxes.utils.flow import FlowHeader
lg = logging.getLogger('detection')

from pox.lib.addresses import IPAddr, IPAddr6


class AbstractDetection(object):
	def __init__(self, box):
		self.box = box

	def process(self, flowHeader, flowList):
		raise NotImplementedError("process() not implemented")		

class Detection(AbstractDetection):
	'''
        The Detection object of the box. It manage all the detection technique you want to implement inside the system
    '''
	MAXFLOWPERDEVICE					=	5
	THRESHOLDHORIZONTALSCANDETECTION	=	20
	THRESHOLDVERTICALSCANDETECTION		=	5
	# from pox.boxes.proto.utils.tools import Alert
	def __init__(self, box):
		AbstractDetection.__init__(self, box)

	def policyComplianceDetection(self, deviceIP, devicePort, flowList):
		"""
		Check if a our device get a communication respecting its policy.

		@type deviceIP: IPAddr/IPAddr6
		@param deviceIP: The suspicious external IP
		@type flowList: Flowlist
		@param flowList: The flowlist of outside connections

		@rtype: bool
		@return: Send true If a device is behaving strangely by having contact with too much devices. if we find a scanning pattern (#pkts < threshold or #connection_duration too short)
		"""
		policy = self.box.policyList[deviceIP]
		deviceSet = flowList.ipSet
		if policy.openPorts is None:
			return True
		elif devicePort in policy.openPorts:
			return True
		elif len (deviceSet[deviceIP]) < policy.maxFlowNumber[deviceIP]:
			return True
		else:
			return False

	def scanDectection(self, deviceIP, flowList):
		"""
		Check if a suspicious device is scanning a network.

		@type deviceIP: IPAddr/IPAddr6
		@param deviceIP: The suspicious external IP
		@type flowList: Flowlist
		@param flowList: The flowlist of outside connections

		@rtype: bool
		@return: Send true If a device is behaving strangely by having contact with too much devices. if we find a scanning pattern (#pkts < threshold or #connection_duration too short)
		"""
		deviceSet = flowList.ipSet
		deviceFlow = flowList.ipFlows
		if not deviceIP in deviceFlow:
			return False
		else:
			# Horizontal scan if one external have more than threshold connection
			if len(deviceSet[deviceIP]) > THRESHOLDHORIZONTALSCANDETECTION:
				return True
			else:
				# Vertical scan when a suspicious device had connection with many port of a particular contacted device.
				for contactedDeviceIP in deviceSet[deviceIP]:
					if len(deviceSet[deviceIP][contactedDeviceIP]) > THRESHOLDVERTICALSCANDETECTION:
						return True
				return False
		# Vertical scan (Very noisy)
		# deviceFlow = flowList.ipFlows
		# suspicious[]
		# if not deviceIP in deviceFlow:
		# 	return False
		# else:
		# 	for flowheader in deviceFlow[deviceIP]:
		# 		ips, dport = flowheader.toTuple(deviceIP)
		# 		if dport < 1024:
		# 			suspicious.add(ips)
		# ipSet = flowList.ipSet
		# suspectSet = Counter()
		# for ip in ipSet:
		# 	if len(ipSet[ip]) > MAXFLOWPERDEVICE:
		# 		suspectSet.add(deviceIP) 
		# if suspectSet is None: 
		# 	return False
		# if len(suspectSet) > 

	def dosDetection(self, deviceIP, flowList):
		"""
		Check if a our device is under a dos attack.

		@type deviceIP: IPAddr/IPAddr6
		@param deviceIP: Our device IP
		@type flowList: Flowlist
		@param flowList: The flowlist of outside connections

		@rtype: (bool, of.match)
		@return: Send (true, flow) if the throughput coming to our devices is above the threshold (#pkts size/flow duration > threshold) and (false, None) when nothing is detected
		"""
		if not self.box.isOurDevice(deviceIP):
			return False, None
		deviceFlow = flowList.ipFlows[deviceIP]
		for flow in deviceFlow:
			if len(flow.actions) > 0 and flow.packet_count > THRESHOLDPACKETCOUNT and flow.byte_count / (flow.duration_sec + 10**-9 * flow.duration_nsec) > THRESHOLDDOSTHROUPUT:
				return True, flow
		return False, None

	def ddosDetection(self, deviceIP, flowList):
		"""
		Check if a our device is under a ddos attack.

		@type deviceIP: IPAddr/IPAddr6
		@param deviceIP: Our device IP
		@type flowList: Flowlist
		@param flowList: The flowlist of outside connections

		@rtype: (bool, of.match)
		@return: Send (true, flow) if the throughput coming to our devices is above the threshold (#pkts size/flow duration > threshold) and (false, None) when nothing is detected
		"""
		if not self.box.isOurDevice(deviceIP):
			return False, None
		deviceFlow = flowList.ipFlows[deviceIP]
		allByteCount = 0
		nbrDevices = 0
		flows = []
		for flow in deviceFlow:
			allByteCount += flow.byte_count
			if len(flow.actions) > 0 and flow.duration_sec > THRESHOLDDDOSTHROUPUT:
				nbrDevices += 1
				flows.append(flow)
		if allByteCount > THRESHOLDDDOSBYTESIZE and nbrDevices >= THRESHOLDDDOSRATIONUMBERDEVICE * len(deviceFlow):
			return True, flows
		return False, None

	def process(self, flowHeader, flowList):
		import pox.boxes.tools.Alert
		if not self.policyComplianceDetection(flowheader.dip, flowHeader.dport, flowList):
			return Alert.COMPLIANCE
		# elif scanDectection(flowheader.sip, flowList):
		# 	return Alert.SCAN
		elif self.dosDetection(flowheader.dip, flowList):
			return Alert.DOS
		elif self.ddosDetection(flowheader.dip, flowList):
			return Alert.DDOS
		else :
			return None