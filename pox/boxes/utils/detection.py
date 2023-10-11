import logging
import pox.openflow.libopenflow_01 as of

from pox.lib.util import initHelper
from pox.boxes.utils.tools import Permission, Alert
from pox.boxes.utils.flow import FlowHeader
log = logging.getLogger('detection')

from pox.lib.addresses import IPAddr, IPAddr6


class AbstractDetection(object):
	def __init__(self, box):
		self.box = box
	
	def process(self, **kwargs):
		raise NotImplementedError("process() not implemented")		

class Detection(AbstractDetection):
	'''
        The Detection object of the box. It manage all the detection technique you want to implement inside the system
    '''
	MAXFLOWPERDEVICE					= 5
	THRESHOLDSCANDETECTION				= 20
	THRESHOLDVERTICALSCANDETECTION		= 20
	THRESHOLDDOSTHROUPUT 				= 200
	THRESHOLDDDOSDURATION 				= 15
	THRESHOLDDDOSBYTESIZE				= 50*10**3
	THRESHOLDDDOSRATIONUMBERDEVICE		= (4.0/5)
	THRESHOLDPACKETCOUNT 				= 5
	# from pox.boxes.proto.utils.tools import Alert
	def __init__(self, box):
		AbstractDetection.__init__(self, box)
		# self._init(kwargs)
	
	def policyComplianceDetection(self, deviceIP, devicePort, flowList, **kwargs):
		"""
		Check if a our device get a communication respecting its policy.

		@type deviceIP: IPAddr/IPAddr6
		@param deviceIP: The suspicious external IP
		@type flowList: Flowlist Set
		@param flowList: The flowlist of outside connections

		@rtype: bool
		@return: Send true If a device is behaving strangely by having contact with too much devices. if we find a scanning pattern (#pkts < threshold or #connection_duration too short)
		"""
		policy = self.box.policyList[deviceIP]
		if policy.openPorts is None:
			return True
		elif devicePort in policy.openPorts:
			return True
		elif len (flowList[deviceIP]) < policy.maxFlowNumber[deviceIP]:
			return True
		else:
			return False

	def scanDetection(self, **kwargs):
		"""
		Check if a suspicious device is scanning a network.

		@type deviceIP: IPAddr/IPAddr6
		@param deviceIP: The suspicious external IP
		@type flowList: Flowlist
		@param flowList: The flowlist of outside connections

		@rtype: bool
		@return: Send true If a device is behaving strangely by having contact with too much devices. if we find a scanning pattern (#pkts < threshold or #connection_duration too short)
		"""
		deviceIP = None if 'deviceIP' not in kwargs else kwargs['deviceIP']
		flowList = None if 'flowList' not in kwargs else kwargs['flowList']
		log.debug("scanDetection deviceIP: %s" % (deviceIP))
		# log.debug("scanDetection deviceIP: %s flowList: %s" % (deviceIP, flowList))
		deviceSet = flowList.ipSet
		deviceFlow = flowList.ipFlows
		if deviceIP not in deviceSet:
			return
		else:
			# Horizontal scan if one external have more than threshold connection
			if len(deviceSet[deviceIP]) > Detection.THRESHOLDSCANDETECTION:
				self.box.alertList.add(deviceIP, Alert(Alert.SCAN, FlowHeader(sip=deviceIP), None))
				return
			else:
				# Vertical scan when a suspicious device had connection with many port of a particular contacted device.
				for contactedDeviceIP in deviceSet[deviceIP]:
					if len(deviceSet[deviceIP][contactedDeviceIP]) > Detection.THRESHOLDVERTICALSCANDETECTION:
						return True
				return False

	def dosDetection(self, **kwargs):
		"""
		Check if a our device is under a dos attack.
		
		@type kwargs: dictionary
		@param kwargs: Our device IP
		@type deviceIP: IPAddr/IPAddr6
		@param deviceIP: Our device IP
		@type flowList: Flowlist
		@param flowList: The flowlist of outside connections

		@rtype: (bool, of.match)
		@return: Send (true, flow) if the throughput coming to our devices is above the threshold (#pkts size/flow duration > threshold) and (false, None) when nothing is detected
		"""
		deviceIP = None if 'deviceIP' not in kwargs else kwargs['deviceIP']
		flowList = None if 'flowList' not in kwargs else kwargs['flowList']
		if deviceIP is None or flowList is None:
			log.error("dosDetection device ip: %s, flowList: %s", deviceIP, flowList)
		outstr = "["
		for flh in flowList:
				outstr += str(flh)+" "
				outstr += flowList[flh].show()
				# outstr +="\n"
		outstr +=']'
		log.debug("dosDetection deviceIP: %s flowList: %s" % (deviceIP, outstr))
		found = False
		for flowHeader in flowList:
			flow = flowList[flowHeader]
			if len(flow.actions) > 0:
				log.debug("dosDetection flowHeader: %s packets: %d, bytes: %d, duration: %d, cond0: %s, cond1: %s, cond2: %s" % (flowHeader, flow.packet_count, flow.byte_count, flow.duration_sec + 10**-9 * flow.duration_nsec, len(flow.actions) > 0, flow.packet_count > Detection.THRESHOLDPACKETCOUNT ,flow.byte_count / (flow.duration_sec + 10**-9 * flow.duration_nsec) > Detection.THRESHOLDDOSTHROUPUT))
			if len(flow.actions) > 0 and flow.packet_count > Detection.THRESHOLDPACKETCOUNT and flow.byte_count / (flow.duration_sec + 10**-9 * flow.duration_nsec) > Detection.THRESHOLDDOSTHROUPUT:
				policy = self.box.policyList[flowHeader.dip]
				log.debug("dosDetection duration: %d" % (policy.victim_mitigation['dos']))
				self.box.alertList.add(deviceIP, Alert(Alert.DOS, FlowHeader.fromMatch(flow.match), flow, policy.victim_mitigation['dos']))
				found = True
		return found

	def ddosDetection(self, **kwargs):
		"""
		Check if a our device is under a ddos attack.

		@type deviceIP: IPAddr/IPAddr6
		@param deviceIP: Our device IP
		@type flowList: Flowlist
		@param flowList: The flowlist of outside connections

		@rtype: (bool, of.match)
		@return: Send (true, flow) if the throughput coming to our devices is above the threshold (#pkts size/flow duration > threshold) and (false, None) when nothing is detected
		"""
		deviceIP = None if 'deviceIP' not in kwargs else kwargs['deviceIP']
		flowList = None if 'flowList' not in kwargs else kwargs['flowList']
		if deviceIP is None or flowList is None:
			log.error("ddosDetection device ip: %s, flowList: %s", deviceIP, flowList)
		outstr = "["
		for flh in flowList:
				outstr += str(flh)+" "
				outstr += flowList[flh].show()
				# outstr +="\n"
		outstr +=']'
		log.debug("ddosDetection deviceIP: %s flowList: %s" % (deviceIP, outstr))
		found = False
		# if not self.box.isOurDevice(deviceIP):
		# 	return found
		allByteCount 	= 0
		flowheaders 	= []
		flows 			= []
		durations 		= []
		for flowHeader in flowList:
			flow = flowList[flowHeader]
			allByteCount += flow.byte_count
			if len(flow.actions) > 0 and (flow.duration_sec + 10**-9 * flow.duration_nsec) > Detection.THRESHOLDDDOSDURATION:
				policy = self.box.policyList[flowHeader.dip]
				flowheaders.append(FlowHeader.fromMatch(flow.match))
				flows.append(flow)
				durations.append(policy.victim_mitigation['ddos'])

		log.debug("ddosDetection flowHeader: %s devices: %d, bytes: %d, cond1: %s, cond2: %s" % (flowHeader, len(flowheaders), allByteCount, allByteCount > Detection.THRESHOLDDDOSBYTESIZE, len(flowheaders) >= Detection.THRESHOLDDDOSRATIONUMBERDEVICE * len(flowList)))

		if allByteCount > Detection.THRESHOLDDDOSBYTESIZE and len(flowheaders) >= Detection.THRESHOLDDDOSRATIONUMBERDEVICE * len(flowList):
			self.box.alertList.add(deviceIP, Alert(Alert.DDOS, flowheaders, flows, durations))
			found = True
		return found

	def process(self, flowList, **kwargs):
		import time
		for ip in list(flowList.ipFlows.keys()):
			log.debug("check %s " % (ip))
			if not self.box.isOurDevice(ip):
				continue
			
			# if self.scanDetection(deviceIP=ip, flowList=flowList):
			# 	log.debug("Scan detected for ip: %s" % (ip))

			# if self.policyComplianceDetection(ip, [], flowList.ipSet):
			# 	log.debug("Policy Compliance detected for ip: %s" % (ip))

			if self.ddosDetection(deviceIP=ip, flowList=flowList.ipFlows[ip]):
				log.debug("DDoS detected on ip: %s at %d" % (ip, time.time()))

			if self.dosDetection(deviceIP=ip, flowList=flowList.ipFlows[ip]):
				log.debug("DoS detected on ip: %s at %d" % (ip, time.time()))