import time
from pox.lib.util import initHelper

class Policy(object):
	DEFAULT_POLICY = {
		'whitelist':[],
		'permission':{'duration' : 30, 'maxPacketSize' : 1504, 'maxFlowNumber' : 10},
		'openPorts' : {1: [0, 8], 6: [80, 443], 17: [53, 80, 443]},
		'victim_mitigation' : {'scan' : 100, 'dos' : 50, 'ddos' : 20, 'reflection' : 50},
		'perpetrator_mitigation' : {'scan' : 10000, 'dos' : 500, 'ddos' : 200, 'reflection' : 500}
	}
	def __init__(self, deviceIP, **kwargs):
		self.deviceIP 					= deviceIP
		self._whitelist 				= kwargs['whitelist'] if 'whitelist' in kwargs else None
		self._permission 				= kwargs['permission'] if 'permission' in kwargs else None
		self._openPorts 				= kwargs['openPorts'] if 'openPorts' in kwargs else None
		self._victim_mitigation 		= kwargs['victim_mitigation'] if 'victim_mitigation' in kwargs else None
		self._perpetrator_mitigation 	= kwargs['perpetrator_mitigation'] if 'perpetrator_mitigation' in kwargs else None

	@property
	def whitelist(self):
		return self._whitelist if self._whitelist is not None else Policy.DEFAULT_POLICY['whitelist']
	
	@property
	def permission(self):
		return self._permission if self._permission is not None else Policy.DEFAULT_POLICY['permission']

	@property
	def openPorts(self):
		return self._openPorts if self._openPorts is not None else Policy.DEFAULT_POLICY['openPorts']
	
	@property
	def victim_mitigation(self):
		return self._victim_mitigation if self._victim_mitigation is not None else Policy.DEFAULT_POLICY['victim_mitigation']

	@property
	def perpetrator_mitigation(self):
		return self._perpetrator_mitigation if self._perpetrator_mitigation is not None else Policy.DEFAULT_POLICY['perpetrator_mitigation']

	def __eq__(self, other):
		if not isinstance(other, self): return False
		return (self.deviceIP, self.maxPacketSize, self.maxFlowNumber, self.openPorts, self.policyList) == (other.deviceIP, other.maxPacketSize, other.maxFlowNumber, other.openPorts, self.policyList)

	def __ne__(self, other):
		return not self.__eq__(self, other)

	def __str__(self):
		return "[deviceIP %s, maxPacketSize %s, maxFlowNumber %s, openPorts %s]", (self.deviceIP, self.maxPacketSize, self.maxFlowNumber, self.openPorts)

	def __repr__(self):
		return self.__str__()

class Permission(object):
	def __init__(self, decision, duration, maxPacketSize):
		self.decision 		= decision
		self.duration 		= duration
		self.maxPacketSize 	= maxPacketSize
		self.timestamp 		= time.time()
		self.stop 			= self.timestamp + duration

	def __eq__(self, other):
		if not isinstance(other, Permission): return False
		if self.decision != other.decision: return False
		if self.duration != other.duration: return False
		if self.maxPacketSize != other.maxPacketSize: return False
		if self.timestamp != other.timestamp: return False
		if self.stop != other.stop: return False
		return True

	def __ne__(self, other):
		return not self.__eq__(self, other)

	def __str__(self):
		return "decision:%s, duration:%d, max flow size:%d, timestamp:%d" % (self.decision, self.duration, self.maxPacketSize, self.timestamp)

	def __repr__(self):
		return self.__str__()

class Alert(object):
	DEFAULT_ALERT_DROP_DURATION = 60

	COMPLIANCE	= 0
	DOS 		= 1
	DDOS 		= 2
	SCAN 		= 3
	
	def __init__(self, aType, flowHeader, flow=None, duration=None):
		self.type 	= aType
		self.flowHeader = flowHeader if flowHeader is not None else FlowHeader.fromMatch(flow)
		self.flow 		= flow
		self.duration 	= Alert.DEFAULT_ALERT_DROP_DURATION if duration is None else duration

	def __eq__(self, other):
		if not isinstance(other, Alert): return False
		return (self.type, self.flowHeader, self.flow, self.duration) == (other.type, other.flowHeader, other.flow, other.duration)

	def __ne__(self, other):
		return not self.__eq__(self, other)

	def __str__(self):
		if self.flow is None:
			return "[type: %s, flowHeader: %s, flow: None, duration:%d]" % (self.type, self.flowHeader, self.duration)
		else:
			if isinstance(self.flowHeader, list):
				outstr = "[type: Alert.DDOS, "
				for i in range(len(self.flowHeader)):
					outstr += "flowHeader '"+str(i)+"': "+str(self.flowHeader[i])+", "
					outstr += "flow '"+str(i)+"': "+str(self.flow[i].show())+", "
					outstr += "duration: "+str(self.duration[i])+" "
				outstr+= "]"
				return outstr
			else:
				return "[type %s, flowHeader %s, flow %s, duration %d]" % (self.type, self.flowHeader, self.flow.show(), self.duration)

	def __repr__(self):
		return self.__str__()