import logging
log = logging.getLogger('mitigation')

import threading, time

from pox.lib.util import initHelper
from pox.lib.addresses import IPAddr, IPAddr6
from pox.boxes.proto.mexp import Mexp, ALERT, ALERT_NOTIF, ALERT_BRDT_RQST
from pox.boxes.utils.mylist import BoxList
from pox.boxes.utils.tools import Alert, Policy
from pox.boxes.proto.alert import AlertNotification

class AbstractMitigation(object):
	def __init__(self, box):
		self.box = box
	
	def process(self, **kwargs):
		raise NotImplementedError("process() not implemented")

class Mitigation(AbstractMitigation):
	def __init__(self, box):
		AbstractMitigation.__init__(self, box)

	def process(self, **kwargs):
		switcher = {
			Alert.COMPLIANCE: self.complianceMitigation,
			Alert.SCAN: self.scanMitigation,
			Alert.DOS: self.dosMitigation,
			Alert.DDOS: self.ddosMitigation
		}
		alert = None if kwargs['alert'] is None else kwargs['alert']
		if alert is not None:
			func = switcher.get(alert.type)
			if func is not None:
				func(**kwargs)
	
	def complianceMitigation(self, **kwargs):
		raise NotImplementedError("complianceMitigation() not implemented")
	
	def scanMitigation(self, **kwargs):
		import time
		log.debug("scanMitigation %s" % (kwargs))
		alert = None if 'alert' not in kwargs else kwargs['alert']
		myDevice = None if 'myDevice' not in kwargs else kwargs['myDevice']
		# flowList = None if self.box.flowCollector is None else self.box.flowCollector.srcFlowList.ipFlows
		flowList = self.box.flowList.ipFlows
		if flowList is None:
			log.error("scanMitigation no flowList: %s and collector: %s", flowList, self.box.flowCollector)
			return
		if alert.flowHeader.sip not in flowList:
			log.error("scanMitigation no flow for malicious IP %s", alert.flowHeader.sip)
		if myDevice is None:
			log.error("scanMitigation, we don't get the device affiliation (victim or perpetrator)")

		if not myDevice:
			box = self.box.messageManager.lookupBox(alert.flowHeader.sip)
			mexp =  Mexp(version=self.box.messageManager.version, tcode=ALERT, code=ALERT_NOTIF, payload=AlertNotification(version=self.box.messageManager.version, proto=alert.flowHeader.proto, type=Alert.SCAN, sip=alert.flowHeader.sip, duration=Policy.DEFAULT_POLICY['perpetrator_mitigation']['scan']))
			self.box.messageManager.sendAndListen(mexp, box)
			self.box.sendBroadcastAlert(mexp.payload)
		self.box.addrBlacklist.add(time.time() + alert.duration, alert.flowHeader.sip)
		for flowHeader in flowList[alert.flowHeader.sip]:
			if flowHeader.sip != alert.flowHeader.sip:
				continue
			self.box.dropFlow(flowHeader, flowList[alert.flowHeader.sip][flowHeader], alert.duration)
			if flowHeader in self.box.permissionList:
				self.box.permissionList.expire(flowHeader)
			# if flowList:
			# 	for flow in flowList[alert.flowHeader.sip]:
			# 		self.box.dropFlow(flow, policy.victim_mitigation['scan'])
	
	def dosMitigation(self, **kwargs):
		log.debug("dosMitigation %s" % (kwargs))
		alert = None if 'alert' not in kwargs else kwargs['alert']
		myDevice = None if 'myDevice' not in kwargs else kwargs['myDevice']
		log.debug("dosMitigation alert: %s", alert)
		if myDevice is None:
			log.error("dosMitigation, we don't get the device affiliation (victim or perpetrator)")

		if myDevice:
			policy = self.box.policyList[alert.flowHeader.dip]
			if alert.flow is not None:
				if alert.flowHeader.sip not in policy.whitelist:
					self.box.dropFlow(alert.flowHeader, alert.flow, alert.duration)
					### Notify the source
					box = self.box.messageManager.lookupBox(alert.flowHeader.sip)
					mexp =  Mexp(version=self.box.messageManager.version, tcode=ALERT, code=ALERT_NOTIF, payload=AlertNotification(version=self.box.messageManager.version, proto=alert.flowHeader.proto, type=Alert.DOS, sport=alert.flowHeader.sport, dport=alert.flowHeader.dport, sip=alert.flowHeader.sip, dip=alert.flowHeader.dip, duration=policy.perpetrator_mitigation['dos']))
					self.box.messageManager.sendAndListen(mexp, box)
				else:
					log.debug("%s is present inside the whitelist" % alert.flowHeader.sip)
			else:
				log.debug("We are in trouble because no flow exists for %s" % (alert.flowHeader))
		else:
			flow = self.box.flowList.ipFlows[alert.flowHeader.sip][alert.flowHeader]	
			if flow is not None:
				self.box.dropFlow(alert.flowHeader, flow, alert.duration)
			else:
				log.error("We are in trouble because no flow for %s exists for the mitigation" % (alert.flowHeader))

	def ddosMitigation(self, **kwargs):
		log.debug("ddosMitigation %s" % (kwargs))
		alert = None if 'alert' not in kwargs else kwargs['alert']
		myDevice = None if 'myDevice' not in kwargs else kwargs['myDevice']
		# flow = kwargs['flow'] if 'flow' in kwargs else self.box.flowList.ipFlows.get(alert.flowHeader.sip, {})
		log.debug("ddosMitigation alert: %s", alert)
		if myDevice is None:
			log.error("ddosMitigation, we don't get the device affiliation (victim or perpetrator)")
		
		if myDevice:
			policy = self.box.policyList[alert.flowHeader.dip]
			if alert.flowHeader.sip not in policy.whitelist:
				self.box.dropFlow(alert.flowHeader, alert.flow, alert.duration)
				### Notify the source
				box = self.box.messageManager.lookupBox(alert.flowHeader.sip)
				mexp =  Mexp(version=self.box.messageManager.version, tcode=ALERT, code=ALERT_NOTIF, payload=AlertNotification(version=self.box.messageManager.version, proto=alert.flowHeader.proto, type=Alert.DDOS, sport=alert.flowHeader.sport, dport=alert.flowHeader.dport, sip=alert.flowHeader.sip, dip=alert.flowHeader.dip, duration=policy.perpetrator_mitigation['ddos']))
				self.box.messageManager.sendAndListen(mexp, box)
			else:
				log.debug("%s is present inside the whitelist" % alert.flowHeader.sip)
		else:
			flow = self.box.flowList.ipFlows[alert.flowHeader.sip][alert.flowHeader]
			if flow is not None:
				self.box.dropFlow(alert.flowHeader, flow, alert.duration)
			else:
				log.error("We are in trouble because no flow for %s exists for the mitigation" % (alert.flowHeader))