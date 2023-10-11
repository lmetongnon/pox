import logging
log = logging.getLogger('mitigation')

import threading, time

from pox.lib.util import initHelper
from pox.lib.addresses import IPAddr, IPAddr6
from pox.boxes.proto.mexp import Mexp, ALERT, ALERT_NOTIF, ALERT_BRDT
from pox.boxes.utils.mylist import BoxList
from pox.boxes.utils.tools import Alert
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
		log.debug("scanMitigation %s" % (kwargs))
		alert = None if 'alert' not in kwargs else kwargs['alert']
		flowlist = None if 'flowlist' not in kwargs else kwargs['flowlist']
		myDevice = None if 'mydevice' not in kwargs else kwargs['myDevice']
		policy = self.box.policyList[alert.flowHeader.dip]
		if myDevice:
			import time
			self.box.addrBlacklist.add(time.time() + policy.perpetrator_mitigation['scan'], alert.flowHeader.sip)
		else:
			if flowlist:
				for flow in flowlist[alert.flowHeader.sip]:
					self.box.dropFlow(flow, policy.victim_mitigation['scan'])
	
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