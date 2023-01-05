import time

class Policy(object):
	def __init__(self, deviceIP, maxPacketSize, maxFlowNumber):
		self.deviceIP = deviceIP
		self.maxPacketSize = maxPacketSize
		self.maxFlowNumber = maxFlowNumber

	def __eq__(self, other):
		if not isinstance(other, Policy): return False
		if self.deviceIP != other.deviceIP: return False
		if self.maxPacketSize != other.maxPacketSize: return False
		if self.maxFlowNumber != other.maxFlowNumber: return False
		return True

	def __ne__(self, other):
		return not self.__eq__(self, other)

	def __str__(self):
		return "[deviceIP %s, maxPacketSize %s, maxFlowNumber %s]", (self.deviceIP, self.maxPacketSize, self.maxFlowNumber)

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
		return "decision:%s, duration:%s, max flow size:%s, %timestamp:%s" % (self.decision, self.duration, self.maxPacketSize, self.timestamp)

class Alert(object):
	def __init__(self, deviceIP, alertType, flow=None):
		self.deviceIP 	= deviceIP
		self.alertType 	= alertType
		self.flow 		= flow

	def __eq__(self, other):
		if not isinstance(other, Alert): return False
		if self.deviceIP != other.deviceIP: return False
		if self.alertType != other.alertType: return False
		if self.flow != other.flow: return False
		return True

	def __ne__(self, other):
		return not self.__eq__(self, other)

	def __str__(self):
		return "[deviceIP %s, alertType %s, flow %s]" % (self.deviceIP, self.alertType, self.flow)