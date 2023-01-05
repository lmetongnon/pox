from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr, IPAddr6

from pox.boxes.manager import Rmanager 
from pox.boxes.utils.mylist import List, PermissionList
from pox.boxes.utils.flow import FlowHeader, Flow, getFlowheader
from pox.boxes.proto.permission import PermissionRequest, PermissionReply
from pox.boxes.proto.mexp import PERMISSION, PERMISSION_RQST, PERMISSION_RPLY
# from pox.boxes.utils.tools import FlowHeader, Flow, getFlowheader

import time

log = core.getLogger('rbox')

class Rbox(object):
	DEFAULT_PERMISSION_DROP_DURATION = 100
	DEFAULT_ALERT_DROP_DURATION = 100

	__instance = None

	@staticmethod
	def getInstance(connection, ip, port, networks):
		if Rbox.__instance is None:
			Rbox(connection, ip, port, networks)
		else:
			Rbox.__instance.connection = connection
			connection.addListeners(Rbox.__instance)
		return Rbox.__instance

	def __init__(self, connection, ip, port, networks):
		
		Rbox.__instance = self
		# Keep track of the connection to the switch so that we can
		# send it messages!
		self.connection = connection

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

		self.flowList = List()

		self.eventList = List()
		
		# This binds our PacketIn event listener
		connection.addListeners(self)

	# standard functions flood, send drop
	def flood (self, event, message = None):

		""" Floods the packet """
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
		"""	send packet in messages to the switch. """
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
		packet = event.parsed
		if not packet.parsed:
			log.warning()
			return
		if self.isControlPacket(packet):
			self.send(event)
		else:
			self.handle(event)

	def handle(self, event):
		""" 
		This code will be executed for every non control packet.
		"""
		packet = event.parsed # This is the parsed packet data.
		flowHeader = getFlowheader(packet.next)
		log.debug("handle ethernet of type %d, ports %s -> %s."
			  % (packet.type, packet.src, packet.dst))
		log.debug("handle flowHeader %s" % flowHeader)
		log.debug("IP %d %d %s => %s", packet.next.v, packet.next.protocol, packet.next.srcip, packet.next.dstip)

		outgoingMessage = False
		for net in self.networks:
			if flowHeader.sip.in_network(net):
				outgoingMessage = True
				break

		permission = self.permissionList[flowHeader]
		if outgoingMessage:
			# outgoing Communication
			self.outgoingMessage(event, permission, flowHeader)
		else:
			# incoming Communication
			# Check distributed scanning attacks
			if self.scanPattern(flowHeader.sip):
				log.debug("Scan pattern attacks detect from %s" % flowHeader.sip)
				self.drop(event, Rbox.DEFAULT_ALERT_DROP_DURATION)		
			self.incomingMessage(event, permission, flowHeader)

 
		if permission :
			# Permission exists
			remainingTime = (time.time() - permission.timestamp)
			if permission.decision and permission.duration > remainingTime:
				log.debug("handle send the message of %s" % flowHeader)
				self.send(event, 1, remainingTime, remainingTime) 
		else :
			box = self.messageManager.boxRecords[flowHeader.dip]
			if box is None:
				log.debug("No Box exists for %s" % flowHeader.dip)
				self.drop(event, Rbox.DEFAULT_PERMISSION_DROP_DURATION)
			else:
				permissionRequest = PermissionRequest(sip=flowHeader.sip, dip=flowHeader.dip, proto=flowHeader.proto, sport=flowHeader.sport, dport=flowHeader.dport, duration=10)
				self.messageManager.createMessage(event, PERMISSION, PERMISSION_RQST, permissionRequest, flowHeader.dip)
	
	def incomingMessage(self, permission, flowHeader):
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
			box = self.getRboxdetail(flowHeader.dip)
			if box is not None:
				# Default Policies
				log.debug("No Box exists for %s" % flowHeader.dip)
				self.drop(event, Rbox.DEFAULT_PERMISSION_DROP_DURATION)
			else:
				# Alert because message come after permission is over
				log.debug("handle incoming packet without permission")
				alertRequest = AlertNotification(sip=flowHeader.sip, dip=flowHeader.dip, proto=flowHeader.proto, alertType=0, sport=flowHeader.sport, dport=flowHeader.dport, duration=Rbox.DEFAULT_ALERT_DROP_DURATION)
				self.messageManager.createMessage(event, ALERT, ALERT_NOTIF, alertRequest, flowHeader.sip)
				self.drop(event, Rbox.DEFAULT_ALERT_DROP_DURATION)
	
	# def getRboxdetail(self, endUserAddress):
	# 	box = self.messageManager.boxRecords[endUserAddress]
	# 	if box is None:
	# 		searchRequest = 

	def requestPermission(self, permRqst):
		""" 
		When a permission request come, check if the device in its current situation can handle it.
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

	def replyPermission(self, mexp):			
		""" 
		When we get a permission reply, check if the device in its current situation can handle it.
		"""
		permReply = mexp.payload
		if permReply.decision:
			event = self.getEvent(mexp.mid - 1)
			self.send(event, priority=1, idleTimeout=permReply.duration, hardTimeout=permReply.duration)
		else:
			self.drop(event, Rbox.DEFAULT_ALERT_DROP_DURATION)

	def setEvent(self, event, mid, dip=None, dport=None):
		self.eventList[mid] = event
	
	def getEvent(self, mid, dip=None, dport=None):
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

# class RboxFlow(object):

# 	def __init__(self, stats):

# 		self.stats = stats
# 		self.box = Rbox.getInstance(None)
# 		self.box.flowcollector = self
# 		self._init()

# 	def _init(self):

# def launch (ip=IPAddr6("2000:db8:1::1"), port=15500, networks=[IPAddr6.parse_cidr("2000:db8::/32")]):
def launch (ip=IPAddr("10.0.0.200"), port=15500, networks=[IPAddr.parse_cidr("10.0.0.0/8")]):
	"""
	Starts the component
	"""
	log.debug("launch %s %s %s" % (ip, port, networks)
		)
	def startSwitch (event):
		log.debug("Controlling %s %s %s %s" % (event.connection, ip, port, networks)
		)
		Rbox.getInstance(event.connection, ip, port, networks)
	
	# def startFlowCollection(event):
	# 	log.debug("Switch Flow collection: %u flows", len(events.stats))
	# 	RboxFlow(event.stat)
	
	core.openflow.addListenerByName("ConnectionUp", startSwitch)
	# core.openflow.addListenerByName("FlowStatsReceived", startFlowCollection)
