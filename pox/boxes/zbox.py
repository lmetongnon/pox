from pox.core import core

from pox.lib.addresses import IPAddr, IPAddr6
from pox.boxes.manager import Zmanager 

from pox.boxes.utils.flow import FlowHeader

log = core.getLogger('zbox')

class Zbox(object):

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
		if Zbox.__instance is None:
			Zbox(connection, ip, port, networks)
		elif connection :
			Zbox.__instance.connection = connection
			connection.addListeners(Zbox.__instance)
		return Zbox.__instance
	
	def __init__(self, connection, ip, port, networks):
		log.debug("__init__ ip=%s, port=%s, networks=%s" % (ip, port, networks,))

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
		self.messageManager = Zmanager(self, ip, port)

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
		if isMalicious(flowHeader):
			self.drop(event, Rbox.DEFAULT_ALERT_DROP_DURATION)
		else:
			self.send(event, 1, 10, 30)
		
	def isMalicious(self, flowHeader):
		return False

# def launch (ip=IPAddr6("2000:db8:1::1"), port=15000, networks=[IPAddr6.parse_cidr("2000:db8::/32")]):
def launch (box_ip="10.0.0.100", box_port=15000, box_networks=["10.0.0.0/8"]):
	log.debug("launch %s %s %s" % (box_ip, box_port, box_networks))
	Zbox.getInstance(None, box_ip, box_port, box_networks)
	def startSwitch (event):
	    Zbox.getInstance(event.connection, box_ip, box_port, box_networks)

	core.openflow.addListenerByName("ConnectionUp", startSwitch)