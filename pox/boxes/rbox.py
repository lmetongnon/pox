from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr, IPAddr6

from pox.boxes.manager import Rmanager 
from pox.boxes.utils.mylist import List, PermissionList, FlowList
from pox.boxes.utils.flow import FlowHeader, Flow
from pox.boxes.proto.permission import PermissionRequest, PermissionReply
from pox.boxes.proto.alert import AlertNotification, AlertBrdc, AlertAck
from pox.boxes.proto.mexp import PERMISSION, PERMISSION_RQST, PERMISSION_RPLY, ALERT, ALERT_NOTIF
from pox.boxes.utils.detection import Detection
from pox.boxes.utils.mitigation import Mitigation
# from pox.boxes.utils.tools import FlowHeader, Flow, getFlowheader

import time, sched, threading

log = core.getLogger('rbox')

class Rbox(object):
	'''
	The class describes the Rear box of the system, which is inside the local network and acts as s firewall.
	'''
	DEFAULT_PERMISSION_DROP_DURATION = 100
	DEFAULT_ALERT_DROP_DURATION = 100

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
		self.policyList = List()

		self.permissionList = PermissionList()

		self.flowList = FlowList(60.0 * 5)

		self.eventList = List()

		self.alertList = List()		
		
		# This binds our PacketIn event listener
		connection.addListeners(self)

		self.updateFlowData()

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

	def isControlPacket(self, packet):
		# Check the packet type
		return packet.type != ethernet.IP_TYPE

	def _handle_PacketIn (self, event):
		"""
		Handles packet in messages from the switch.
		"""
		self.updateFlowData()
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
		log.debug("IP %d %d %s => %s", packet.next.v, packet.next.protocol, packet.next.srcip, packet.next.dstip)

		permission = self.permissionList[flowHeader]
		if self.isOurDevice(flowHeader.sip):
			# outgoing Communication
			self.outgoingMessage(event, permission, flowHeader)
		else:
			# incoming Communication
			# Check distributed scanning attacks
			if self.detection.scanDectection(flowHeader.sip, self.flowList):
				log.debug("Scan pattern attacks detect from %s" % flowHeader.sip)
				self.alertList.add(flowHeader.dip, Alert(Alert.SCAN, flowHeader))
				self.drop(event, Rbox.DEFAULT_ALERT_DROP_DURATION)		
			self.incomingMessage(event, permission, flowHeader)

	def outgoingMessage(self, event, permission:"Permission", flowHeader:"FlowHeader"):
		"""
		We check every new message to see if we should send then or request new permission.
		@type event: 
		@param event: The event related to the message of the end devices 
		@type permission: Permission
		@param permission: None for new communication and the previous permission if the message is related to an old valid communication 
		@type flowHeader: FlowHeader
		@param flowHeader: The flow header of the incoming message
		"""
		if permission :
			# Permission exists
			remainingTime = (time.time() - permission.timestamp)
			if permission.decision and permission.duration > remainingTime:
				log.debug("handle send the message of %s" % flowHeader)
				self.send(event, 1, remainingTime, remainingTime) 
		else :
			box = self.messageManager.lookupBox(flowHeader.dip)
			if box is None:
				log.debug("No Box exists for %s" % flowHeader.dip)
				self.drop(event, Rbox.DEFAULT_PERMISSION_DROP_DURATION)
			else:
				permissionRequest = PermissionRequest(sip=flowHeader.sip, dip=flowHeader.dip, proto=flowHeader.proto, sport=flowHeader.sport, dport=flowHeader.dport, duration=10)
				self.messageManager.createMessage(event, PERMISSION, PERMISSION_RQST, permissionRequest, flowHeader.dip)
	
	def incomingMessage(self, event, permission:"Permission", flowHeader:"FlowHeader"):
		"""
		We check every new message to see if they can go throw.
		@type permission: Permission
		@param permission: None for new communication and the previous permission if the message is related to an old valid communication 
		@type flowHeader: FlowHeader
		@param flowHeader: The flow header of the incoming message
		"""
		#check if packet has permission
		if permission:
			# Permission exists
			remainingTime = (time.time() - permission.timestamp)
			if permission.decision and permission.duration > remainingTime:
				log.debug("handle send the message of %s" % flowHeader)
				self.send(event, 1, remainingTime, remainingTime)
			else:
				log.debug("handle send the message of %s" % flowHeader)
				self.drop(event, DEFAULT_PERMISSION_DROP_DURATION)
		else :
			# box = self.getDeviceRbox(flowHeader.sip)
			box = self.messageManager.lookupBox(flowHeader.sip)
			if box is None:
				# Default Policies
				log.debug("No Box exists for %s" % flowHeader.dip)
				self.drop(event, Rbox.DEFAULT_PERMISSION_DROP_DURATION)
			else:
				# Alert because message come after permission is over
				log.debug("handle incoming packet without permission %s" %(flowHeader))
				alertRequest = AlertNotification(sip=flowHeader.sip, dip=flowHeader.dip, proto=flowHeader.proto, alertType=0, sport=flowHeader.sport, dport=flowHeader.dport, duration=Rbox.DEFAULT_ALERT_DROP_DURATION)
				self.messageManager.createMessage(event, ALERT, ALERT_NOTIF, alertRequest, flowHeader.sip)
				self.drop(event, Rbox.DEFAULT_ALERT_DROP_DURATION)
	
	def updateFlowData(self):
		"""
		We update the flow information here periodically for the detection process
		"""
		log.debug ("get_flows")
		self.connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
		if self.flowCollector is not None:
			self.flowCollector.check()
	
	# def getDeviceRbox(self, endUserAddress):
	# 	box = self.messageManager.boxRecords[endUserAddress]
	# 	if box is None:
	# 		searchRequest = 

	def requestPermission(self, permRqst:"PermissionRequest"):
		""" 
		When a permission request come, check if the device in its current situation can handle it.

		@type permRqst: PermissionRequest
		@param permRqst: The request from the sender Rear box

		@rtype: PermissionReply
		@return We send the permission reply after checking the device policy and it's current state
		"""
		# duration, maxPacketSize, decision = checkDevice(permRqst):
		# policy = self.policyList[permRqst.dip]
		# nbrFlow = self.getFlow(permRqst.dip, permRqst.dport)
		# decision = True if permRqst.duration <= policy.duration and permRqst.maxPacketSize <= policy.maxPacketSize and permRqst.nbrFlow < policy.maxPacketSize else False
		log.msg("requestPermission %s" % permRqst)
		decision = True
		if decision:
			return PermissionReply(duration=permRqst.duration, maxPacketSize=permRqst.maxPacketSize, decision=decision)
		else:
			return PermissionReply(duration=policy.duration, maxPacketSize=policy.maxPacketSize, decision=decision)

	def replyPermission(self, mexp:"Mexp"):			
		""" 
		When we get a permission reply, we checked the permission and send or drop the end device packet

		@type mexp: Mexp
		@param mexp: the message reply coming from the destination Rear box
		"""
		permReply = mexp.payload
		if permReply.decision:
			event = self.getEvent(mexp.mid - 1)
			self.send(event, priority=1, idleTimeout=permReply.duration, hardTimeout=permReply.duration)
		else:
			self.drop(event, Rbox.DEFAULT_ALERT_DROP_DURATION)

	def setEvent(self, event, mid:int, dip=None, dport=None):
		"""
		We save the event for future when we reach a decision related to end device after exchange with other Box

		@type event:
		@param event:
		@type mid: int
		@param mid: The message ID of the message
		"""
		self.eventList[mid] = event
	
	def getEvent(self, mid:int, dip=None, dport=None):
		"""
		We can get a previous saved event using the right mid, when we reach a decision related to end device after exchange with other Box

		@type mid: int
		@param mid: The message ID of the message

		@rtype event
		@return: The pox controller event where the end device message is saved
		"""
		return self.eventList[mid]
	
	# def checkDevice(self, permRqst):
	# 	policy = self.policyList[permRqst.dip]
	# 	nbrFlow = self.getFlow(permRqst.dip, permRqst.dport)
	# 	decision = True if permRqst.duration <= policy.duration and permRqst.maxPacketSize <= policy.maxPacketSize and permRqst.nbrFlow < policy.maxPacketSize
	# 	if not decision:
	# 		return policy.duration, policy.maxPacketSize, decision
	# 	else:
	# 		return policy.duration, policy.maxPacketSize, decision
		# duration = permRqst.duration if permRqst.duration < policy.duration else policy.duration
		# maxPacketSize = permRqst.maxPacketSize if permRqst.maxPacketSize < policy.maxPacketSize else policy.maxPacketSize
	
	def checkingPermission(self):
		"""
		We check the list of permission with the current time to remove expired device's permission 
		"""
		for key in self.permissionList.keys():
			if (time.time() - self.permissionList[key].timestamp) >= self.self.permissionList[key].duration:
				del self.permissionList[key]

	def checkingAlert(self):
		"""
		We check the list of the alert and started mitigation process
		"""
		for key in self.alertList.keys():
			alert = self.alertList[key].pop()
			if isinstance(alert.flowHeader, list):
				for flowHeader, flow in zip(alert.flowHeader, alert.flow):
					self.mitigation(Alert(alert.alertType, flowHeader, flow))

	def checkingList(self):
		"""
		We check all the list here from time to time
		"""
		self.checkingAlert()
		self.checkingPermission()
		self.updateFlowData()

# def launch (ip=IPAddr6("2000:db8:1::1"), port=15500, networks=[IPAddr6.parse_cidr("2000:db8::/32")]):
def launch (ip=IPAddr("10.0.0.200"), port=15500, networks=[IPAddr.parse_cidr("10.0.0.0/8")]):
	from pox.boxes.flowcollector import FlowCollector
	"""
	Starts the component
	"""
	log.debug("launch %s %s %s" % (ip, port, networks)
		)
	def startSwitch (event):
		log.debug("Controlling %s %s %s %s" % (event.connection, ip, port, networks)
		)
		Rbox.getInstance(event.connection, ip, port, networks)
	
	def startFlowCollection(event):
		log.debug("Switch Flow collection: %u flows", len(event.stats))
		FlowCollector(event.stats)
	
	core.openflow.addListenerByName("ConnectionUp", startSwitch)
	core.openflow.addListenerByName("FlowStatsReceived", startFlowCollection)
