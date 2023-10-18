from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr, IPAddr6

from pox.boxes.proto.mexp import Mexp
from pox.boxes.manager import Rmanager 
from pox.boxes.utils.mylist import List, PermissionList, FlowList, PolicyList, AlertList, BlackList
from pox.boxes.utils.flow import FlowHeader, Flow
from pox.boxes.proto.permission import PermissionRequest, PermissionReply
from pox.boxes.proto.alert import AlertNotification, AlertBrdcRqst, AlertAck
from pox.boxes.proto.mexp import PERMISSION, PERMISSION_RQST, PERMISSION_RPLY, ALERT, ALERT_NOTIF, ALERT_ACK, ALERT_BRDT_RQST
from pox.boxes.utils.detection import Detection
from pox.boxes.utils.mitigation import Mitigation
from pox.boxes.utils.tools import Permission, Alert

import time, sched, threading

log = core.getLogger('rbox')

class Rbox(object):
	'''
	The class describes the Rear box of the system, which is inside the local network and acts as s firewall.
	'''
	DEFAULT_PERMISSION_DROP_DURATION 		= 100
	DEFAULT_ALERT_DROP_DURATION 			= 100
	DEFAULT_PERMISSION_OUTGOING_DURATION 	= 30

	__instance = None

	@staticmethod
	def getInstance(connection=None, ip=None, port=None, networks=None):
		"""
		To allow only one instance of the Rear Box because the openflow's call happen a lot
		@type connection:
		@param connection:
		@type ip: IPAddr/IPAddr6
		@param ip: The address of the Rearbox
		@type port: int
		@param port: The port use by the rearbox (the controller port)
		@type networks: IPAddr/IPAddr6 or list
		@param networks: The networks protect by the Rearbox
		"""
		if Rbox.__instance is None:
			Rbox(connection, ip, port, networks)
		elif connection :
			Rbox.__instance.connection = connection
			connection.addListeners(Rbox.__instance)
		return Rbox.__instance

	def __init__(self, connection, ip, port, networks):
		
		Rbox.__instance = self
		# Keep track of the connection to the switch so that we can
		# send it messages!
		self.connection = connection

		self.flowCollector = None

		# The box IP address
		self.ip = ip
		if networks:
			networks = networks.replace(',', ' ').split()
			networks = list(net for net in networks)
		self.networks = set()		
		if not isinstance(networks, list):
			networks = [networks]
		
		if networks[0].find(':') != -1 :
			for net in networks:
				self.networks.add(IPAddr6.parse_cidr(net))
		else :
			for net in networks:
				self.networks.add(IPAddr.parse_cidr(net))
		
		# The box message manager
		self.messageManager = Rmanager(self, ip, port)

		# Use this table to keep track of which ethernet address is on
		# which switch port (keys are MACs, values are ports).
		self.macToPort = {}

		#The list of the devices policy (IP => policy) 
		self.policyList = PolicyList()

		self.permissionList = PermissionList()

		self.flowList = FlowList(60.0 * 5)

		self.eventList = List()

		self.alertList = AlertList()		
		
		self.addrBlacklist = BlackList()
		
		# This binds our PacketIn event listener
		connection.addListeners(self)

		self.flowCollectorCheck()

		# checking for automatic list
		# For the scheduling check
		self.watchtimer = sched.scheduler(time.time, time.sleep)
		self.watchtimer.enter(.5, 1, self.checkingList, ())
		threading.Thread(target=self.watchtimer.run).start()

    	# Detection and mitigation object
		self.detection = Detection(self)
		self.mitigation = Mitigation(self)

	# standard functions flood, send drop
	def flood (self, event, message = None):
		"""
		Floods the packet
		@type event:
		@param event:
		@type message: str
		@param message: just a comment to show the message we flood
		"""
		packet = event.parsed # This is the parsed packet data.
		packetIn = event.ofp # The actual ofp_packet_in message.zero
		switchPort = event.port # the port on the switch

		msg = of.ofp_packet_out()
		if time.time() - self.connection.connect_time >= 0:
			if message is not None:
				log.debug(message)
			log.debug("flood %s -> %s", packet.src, packet.dst)
			# OFPP_FLOOD is optional; on some switches you may need to change
			# this to OFPP_ALL.
			msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
		else:
			log.info("Holding down flood for %s", dpid_to_str(event.dpid))
			pass
		msg.data = packetIn
		msg.in_port = switchPort
		self.connection.send(msg)

	def send(self, event, priority=None, idleTimeout=10, hardTimeout=30):
		"""
		send packet in messages to the switch.
		"""
		packet = event.parsed
		self.macToPort[packet.src] = event.port # 1

		if packet.dst.is_multicast:
			self.flood(event) # 3a
		else:
			if packet.dst not in self.macToPort: # 4
				self.flood(event, "Port for %s unknown -- flooding" % (packet.dst,)) # 4a
			else:
				port = self.macToPort[packet.dst]
				if port == event.port: # 5
					# 5a
					log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
					  % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
					self.drop(packet, event.ofp, event.port, idleTimeout)
					return
				# 6
				log.debug("installing flow for %s.%i -> %s.%i" %
						  (packet.src, event.port, packet.dst, port))
				msg = of.ofp_flow_mod()
				msg.match = of.ofp_match.from_packet(packet, event.port)
				msg.idle_timeout = idleTimeout
				msg.hard_timeout = hardTimeout
				if priority is not None:
					msg.priority = priority
				msg.actions.append(of.ofp_action_output(port = port))
				msg.data = event.ofp # 6a
				self.connection.send(msg)
  
	def drop (self, event, duration = None):
		"""
		Drops this packet and optionally installs a flow to continue
		dropping similar ones for a while
		"""
		if duration is not None:
			if not isinstance(duration, tuple):
				duration = (duration, duration)
				msg = of.ofp_flow_mod()
				msg.match = of.ofp_match.from_packet(event.parsed)
				msg.idle_timeout = duration[0]
				msg.hard_timeout = duration[1]
				msg.priority = 1
				msg.buffer_id = event.ofp.buffer_id
				self.connection.send(msg)
		elif event.ofp.buffer_id is not None:
			msg = of.ofp_packet_out()
			msg.buffer_id = event.ofp.buffer_id
			msg.priority = 1
			msg.in_port = event.port
			self.connection.send(msg)

	def dropFlow (self, flowheader, flow, duration = None):
		"""
		Drops this packet and optionally installs a flow to continue
		dropping similar ones for a while
		"""
		if flow is None:
			log.debug("dropFlow flowheader: %s, duration: %s, flow: None" % (flowheader, duration))
		else:
			log.debug("dropFlow flowheader: %s, duration: %s, flow: %s" % (flowheader, duration, flow.show()))
		if not isinstance(duration, tuple):
			duration = (duration, duration)
		if flow is not None:
			msg = of.ofp_flow_mod()
			msg.match.dl_type = 0x800 # IPV4
			msg.match = flow.match
			msg.idle_timeout = duration[0]
			msg.hard_timeout = duration[1]
			msg.actions = []
			msg.priority = 1
			self.connection.send(msg)
		elif flowheader is not None:
			msg = of.ofp_flow_mod()
			msg.match.dl_type = 0x800 # IPV4
			msg.match.nw_proto = flowheader.proto
			msg.match.nw_src = flowheader.sip
			msg.match.tp_src = flowheader.sport
			msg.match.nw_dst = flowheader.dip
			msg.match.tp_dst = flowheader.dport
			msg.idle_timeout = duration[0]
			msg.hard_timeout = duration[1]
			msg.actions = []
			msg.priority = 1
			self.connection.send(msg)
		else:
			log.error("dropFlow no flowHeader or flow to drop")
	
	def isControlPacket(self, packet):
		# Check the packet type
		return packet.type != ethernet.IP_TYPE

	def _handle_PacketIn (self, event):
		"""
		Handles packet in messages from the switch.
		"""
		# self.flowCollectorCheck()
		packet = event.parsed
		if not packet.parsed:
			log.warning()
			return
		if self.isControlPacket(packet):
			self.send(event)
		else:
			self.handle(event)

	def isOurDevice(self, deviceIP):
		for net in self.networks:
			if deviceIP.in_network(net):
				return True
		return False
	
	def handle(self, event):
		""" 
		This code will be executed for every non control packet. we check if the message is coming or leaving from the network and send different requests
		@type event:
		@param event: The message from the end device
		"""
		packet = event.parsed # This is the parsed packet data.
		flowHeader = FlowHeader.fromPacket(packet.next)
		log.debug("handle ethernet of type %d, ports %s -> %s."
			  % (packet.type, packet.src, packet.dst))
		log.debug("handle flowHeader %s" % flowHeader)
		log.debug("handle IP %d %d %s => %s", packet.next.v, packet.next.protocol, packet.next.srcip, packet.next.dstip)
		log.debug("handle %s => %s", flowHeader, self.permissionList[flowHeader])
		permission = self.permissionList[flowHeader]
		# permission = None
		if self.isOurDevice(flowHeader.sip):
			# outgoing Communication
			self.outgoingMessage(event, permission, flowHeader)
		else:
			# incoming Communication
			# Check distributed scanning attacks
			if self.detection.scanDetection(maliciousIP=flowHeader.sip, flowList=self.flowList):
				log.debug("handle scan pattern attacks detect from %s" % flowHeader.sip)
				self.alertList.add(flowHeader.dip, Alert(Alert.SCAN, flowHeader))

				self.drop(event, Rbox.DEFAULT_ALERT_DROP_DURATION)		
			self.incomingMessage(event, permission, flowHeader)

	def outgoingMessage(self, event, permission:"Permission", flowHeader:"FlowHeader"):
		"""
		We check every new message to see if we should send it to then or request new permission first.
		@type event: 
		@param event: The event related to the message of the end devices 
		@type permission: Permission
		@param permission: None for new communication and the previous permission if the message is related to an old valid communication 
		@type flowHeader: FlowHeader
		@param flowHeader: The flow header of the incoming message
		"""
		if flowHeader.sip in self.addrBlacklist:
			# COMPLAINT
			log.debug("outgoingMessage drop message cause %s inside blacklist" % flowHeader)
			self.drop(event, Rbox.DEFAULT_ALERT_DROP_DURATION)
			return

		if self._unreachableTraffic(flowHeader):
			flowHeader = flowHeader.flip()
			log.debug("outgoingMessage Unreacheable Reply stop %s" % flowHeader)
			mexp = Mexp(version=self.messageManager.version, tcode=ALERT, code=ALERT_NOTIF, payload=AlertNotification(version=self.messageManager.version, proto=flowHeader.proto, type=Alert.SCAN, sport=flowHeader.sport, dport=flowHeader.dport, sip=flowHeader.sip, dip=flowHeader.dip, duration=Rbox.DEFAULT_ALERT_DROP_DURATION))
			box = self.messageManager.lookupBox(flowHeader.sip)
			self.messageManager.sendAndListen(mexp, box)
				# self.messageManager.createMessage(event, ALERT, ALERT_NOTIF, alertRequest, flowHeader.sip)
			self.drop(event, Rbox.DEFAULT_ALERT_DROP_DURATION)
			return

		if permission :
			# Permission exists
			remainingTime = (time.time() - permission.timestamp)
			if permission.decision and permission.duration > remainingTime:
				log.debug("outgoingMessage send the message of %s with %d remaining Time" % (flowHeader, remainingTime))
				self.send(event, 1, permission.duration, permission.duration) 
		else :
			box = self.messageManager.lookupBox(flowHeader.dip)
			if box is None:
				log.debug("outgoingMessage No Box exists for %s" % flowHeader.dip)
				self.drop(event, Rbox.DEFAULT_PERMISSION_DROP_DURATION)
			else:
				mexp = Mexp(version=self.messageManager.version, tcode=PERMISSION, code=PERMISSION_RQST, payload=PermissionRequest(sip=flowHeader.sip, dip=flowHeader.dip, proto=flowHeader.proto, sport=flowHeader.sport, dport=flowHeader.dport, duration=Rbox.DEFAULT_PERMISSION_OUTGOING_DURATION))
				self.setEvent(event, mexp.mid, flowHeader)
				self.messageManager.sendAndListen(mexp, box)
				# self.messageManager.createMessage(event, PERMISSION, PERMISSION_RQST, permissionRequest, flowHeader.dip)
	
	def incomingMessage(self, event, permission:"Permission", flowHeader:"FlowHeader"):
		"""
		We check every new message to see if they can go throw.
		@type permission: Permission
		@param permission: None for new communication and the previous permission if the message is related to an old valid communication 
		@type flowHeader: FlowHeader
		@param flowHeader: The flow header of the incoming message
		"""
		if flowHeader.sip in self.addrBlacklist:
			# COMPLAINT
			log.debug("incomingMessage drop message of %s and complain" % flowHeader)
			self.drop(event, Rbox.DEFAULT_ALERT_DROP_DURATION)
		
		#check if packet has permission
		if permission:
			# Permission exists
			remainingTime = (time.time() - permission.timestamp)
			if permission.decision and permission.duration > remainingTime:
				log.debug("incomingMessage get the message of %s with %d remaining Time" % (flowHeader, remainingTime))
				self.send(event, 1, permission.duration, permission.duration)
			else:
				log.debug("incomingMessage drop the message of %s" % flowHeader)
				self.drop(event, Rbox.DEFAULT_PERMISSION_DROP_DURATION)
		else :
			# box = self.getDeviceRbox(flowHeader.sip)
			box = self.messageManager.lookupBox(flowHeader.sip)
			if box is None:
				# Default Policies
				log.debug("incomingMessage No Box exists for %s" % flowHeader.dip)
				self.drop(event, Rbox.DEFAULT_PERMISSION_DROP_DURATION)
			else:
				# Alert because message come after permission is over
				log.debug("incomingMessage incoming packet without permission %s" %(flowHeader))
				mexp = Mexp(version=self.messageManager.version, tcode=ALERT, code=ALERT_NOTIF, payload=AlertNotification(version=self.messageManager.version, proto=flowHeader.proto, type=Alert.COMPLIANCE, sport=flowHeader.sport, dport=flowHeader.dport, sip=flowHeader.sip, dip=flowHeader.dip, duration=Rbox.DEFAULT_ALERT_DROP_DURATION))
				self.messageManager.sendAndListen(mexp, box)
				# self.messageManager.createMessage(event, ALERT, ALERT_NOTIF, alertRequest, flowHeader.sip)
				self.drop(event, Rbox.DEFAULT_ALERT_DROP_DURATION)
	
	def flowCollectorCheck(self):
		"""
		We update the flow information here periodically for the detection process
		"""
		log.debug ("flowCollectorCheck start")
		self.connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
		if self.flowCollector is not None:
			log.debug ("flowCollectorCheck end")
			self.flowCollector.check()
	
	def getPermissionRequest(self, permRqst:"PermissionRequest"):
		""" 
		When a permission request come, check if the device in its current situation can handle it.

		@type permRqst: PermissionRequest
		@param permRqst: The request from the sender Rear box

		@rtype: PermissionReply
		@return We send the permission reply after checking the device policy and it's current state
		"""
		log.debug("getPermissionRequest %s" % permRqst)
		decision, duration, maxPacketSize = self._checkDevice(permRqst)
		flowHeader = FlowHeader(proto=permRqst.proto, sip=permRqst.sip, dip=permRqst.dip, sport=permRqst.sport, dport=permRqst.dport)
		# decision = True
		if decision:
			self.permissionList.add(flowHeader, Permission(decision, duration, maxPacketSize))
			log.debug("getPermissionRequest %s => %s", flowHeader, self.permissionList[flowHeader])
			return PermissionReply(proto=permRqst.proto, sip=permRqst.sip, dip=permRqst.dip, sport=permRqst.sport, dport=permRqst.dport, duration=duration, maxPacketSize=maxPacketSize, decision=decision)
		else:
			return PermissionReply(proto=permRqst.proto, sip=permRqst.sip, dip=permRqst.dip, sport=permRqst.sport, dport=permRqst.dport, duration=duration, maxPacketSize=maxPacketSize, decision=decision)

	def getPermissionReply(self, mid:"int", permReply:"PermissionReply"):
		""" 
		When we get a permission reply, we checked the permission and send or drop the end device packet

		@type mexp: Mexp
		@param mexp: the message reply coming from the destination Rear box
		"""
		flowHeader = FlowHeader(proto=permReply.proto, sip=permReply.sip, dip=permReply.dip, sport=permReply.sport, dport=permReply.dport)
		event = self.getEvent(mid, flowHeader)
		if event is None:
			log.error("We are in trouble")
		else:
			if permReply.decision:
				self.permissionList.add(flowHeader, Permission(permReply.decision, permReply.duration, permReply.maxPacketSize))
				log.debug("getPermissionReply %s => %s", flowHeader, self.permissionList[flowHeader])
				self.send(event, priority=1, idleTimeout=permReply.duration, hardTimeout=permReply.duration)
			else:
				self.drop(event, Rbox.DEFAULT_ALERT_DROP_DURATION)

	def getAlertNotification(self, altNotif:"AlertNotification"):
		""" 
		When an alert notification come, mitigate it if the traffic really exists if not complain.

		@type altNotif: AlertNotification
		@param altNotif: The request from the sender Rear box

		@rtype: ALERT_ACK or COMPLAINT_RQST
		@return We send the ALERT_ACK or the COMPLAINT_RQST after checking the existence of the traffic.
		"""
		log.debug("getAlertNotification %s" % altNotif)
		# Check if I'm sending this traffic, stop and send ack
		flowHeader = FlowHeader(proto=altNotif.proto, sip=altNotif.sip, dip=altNotif.dip, sport=altNotif.sport, dport=altNotif.dport)
		if self._checkTrafficExists(altNotif.type, flowHeader):
			if altNotif.type == Alert.SCAN:
				self.alertList.add(altNotif.sip, Alert(altNotif.type, flowHeader, None, altNotif.duration) )
			else:
				self.alertList.add(altNotif.dip, Alert(altNotif.type, flowHeader, None, altNotif.duration) )
			return ALERT_ACK
		else:
			return COMPLAINT_RQST

	def getAlertBroadcast(self, altBdrc:"AlertNotification"):
		log.debug("getAlertBroadcast %s", altBdrc)
		# dip = IP_ANY if self.messageManager.version in VERSION_MEXP_BOX_IPV4 else IPAddr6.UNDEFINED
		flowHeader = FlowHeader(proto=altBdrc.proto, sip=altBdrc.sip)
		if altBdrc.type == Alert.SCAN:
			self.alertList.add(altBdrc.sip, Alert(altBdrc.type, flowHeader, None, altBdrc.duration))
	
	def sendBroadcastAlert(self, alertMessage:"Mexp"):
		log.debug("sendBroadcastAlert %s", alertMessage)
		if alertMessage.type == Alert.SCAN:
			mexp = Mexp(version=alertMessage.version, tcode=ALERT, code=ALERT_BRDT_RQST, payload=AlertBrdcRqst(version=alertMessage.version, proto=alertMessage.proto, type=alertMessage.type, sip=alertMessage.sip, duration=alertMessage.duration))
			self.messageManager.sendAndListen(mexp, self.messageManager.zbox)
	
	def _checkTrafficExists(self, trafficType:"Alert.type", flowHeader:"FlowHeader") -> bool:
		return True
		# self.flowList.ipFlows[]
	
	def _unreachableTraffic(self, flowHeader:"FlowHeader") -> bool:
		return flowHeader.proto == 1 and flowHeader.sport == 3 and flowHeader.dport == 3
	
	def setEvent(self, event, mid:int, flowHeader:"FlowHeader"):
		"""
		We save the event for future when we reach a decision related to end device after exchange with other Box

		@type event:
		@param event:
		@type mid: int
		@param mid: The message ID of the message
		"""
		self.eventList[(mid, flowHeader)] = event
	
	def getEvent(self, mid:int, flowHeader:"FlowHeader"):
		"""
		We can get a previous saved event using the right mid, when we reach a decision related to end device after exchange with other Box

		@type mid: int
		@param mid: The message ID of the message

		@rtype event
		@return: The pox controller event where the end device message is saved
		"""
		return self.eventList[(mid, flowHeader)]
	
	def _checkDevice(self, permRqst):
		policy = self.policyList[permRqst.dip]
		nbrFlow = 1#self.getFlow(permRqst.dip, permRqst.dport)
		decision = True if permRqst.duration <= policy.permission['duration'] and permRqst.maxPacketSize <= policy.permission['maxPacketSize'] and nbrFlow < policy.permission['maxFlowNumber'] else False
		log.debug("_checkDevice Permission request %s and decision: %s" % (permRqst, decision))
		if decision:
			duration = permRqst.duration if permRqst.duration < policy.permission['duration'] else policy.permission['duration']
			maxPacketSize = permRqst.maxPacketSize if permRqst.maxPacketSize < policy.permission['maxPacketSize'] else policy.permission['maxPacketSize']
			return decision, duration, maxPacketSize
		else:
			return decision, policy.permission['duration'], policy.permission['maxPacketSize']
	
	# def checkingPermission(self):
	# 	"""
	# 	We check the list of permission with the current time to remove expired device's permission 
	# 	"""
	# 	# for k, v in list(data.items()):
	# 	for key in list(self.permissionList.keys()):
	# 		log.debug("checkingPermission %s %d" % (key, (time.time() - self.permissionList[key].timestamp) >= self.permissionList[key].duration))
	# 		if (time.time() - self.permissionList[key].timestamp) >= self.permissionList[key].duration:
	# 			self.permissionList.delete(key)

	# def checkingAlert(self):
	# 	"""
	# 	We check the list of the alert and started mitigation process
	# 	"""
	# 	for key in list(self.alertList.keys()):
	# 		alert = self.alertList.delete(key)
	# 		log.debug("checkingAlert key:%s alert:%s" % (key, alert))
	# 		if isinstance(alert.flowHeader, list):
	# 			for flowHeader, flow in zip(alert.flowHeader, alert.flow):
	# 				self.mitigation.process(alert=Alert(alert.type, flowHeader, flow))
	# 				self.permissionList.delete(flowHeader)
	# 		else:
	# 			self.mitigation.process(alert=alert)
	# 			self.permissionList.delete(alert.flowHeader)

	def checkingList(self):
		"""
		We check all the list here from time to time
		"""
		# self.detection.process(self.flowList, self.alertList)
		self.alertList.check(self)
		self.permissionList.check()
		self.addrBlacklist.check()
		self.flowCollectorCheck()
		self.watchtimer.enter(.5, 1, self.checkingList, ())

# def launch (ip=IPAddr6("2000:db8:1::1"), port=15500, networks=[IPAddr6.parse_cidr("2000:db8::/32")]):
def launch (box_ip=IPAddr("10.0.0.200"), box_port=15500, box_networks=[IPAddr.parse_cidr("10.0.0.0/8")]):
	from pox.boxes.flowcollector import FlowCollector
	"""
	Starts the component
	"""
	log.debug("launch %s %s %s" % (box_ip, box_port, box_networks)
		)
	def startSwitch (event):
		log.debug("Controlling %s %s %s %s" % (event.connection, box_ip, box_port, box_networks)
		)
		Rbox.getInstance(event.connection, box_ip, box_port, box_networks)
	
	def startFlowCollection(event):
		log.debug("Switch Flow collection: %u flows", len(event.stats))
		FlowCollector(event.stats)
	
	core.openflow.addListenerByName("ConnectionUp", startSwitch)
	core.openflow.addListenerByName("FlowStatsReceived", startFlowCollection)