import logging
lg = logging.getLogger('manager')

import random
import threading
import time
import yaml

# from abc import ABC
from pox.lib.addresses import IPAddr, IPAddr6, IP_ANY
from pox.boxes.proto.mexp import Mexp
from pox.boxes.utils.mylist import BoxList

from pox.boxes.proto.activation import ZoneRequest, ZoneReply, RegistrationRequest, RegistrationReply
from pox.boxes.proto.lookup import LookupRequest, LookupDelegateRequest, LookupReply, LookupDelegateReply
from pox.boxes.proto.mexp import ACTIVATION, ALERT, LOOKUP, PERMISSION, POLICY, FLOW, SYNC, COMPLAINT
from pox.boxes.proto.mexp import ZONE_RQST, ZONE_RPLY, REG_RQST, REG_RPLY, MESSAGE_ERR, PERMISSION_RQST, PERMISSION_RPLY, LOOKUP_RQST, LOOKUP_RPLY, LOOKUP_DL_RQST, LOOKUP_DL_RPLY, ALERT_NOTIF, ALERT_ACK, ALERT_BRDT_RQST, ALERT_BRDT_RPLY, ALERT_DL_BRDT_RQST, ALERT_DL_BRDT_RPLY, COMPLAINT_RQST, COMPLAINT_INQ, COMPLAINT_RPLY, COMPLAINT_MITI

from socket import *

bufferSize = 4096
TBox = [('', 15700)]
class MessageManager(object):
	'''
	Class managing message exchange between the boxes
	'''
	def __init__(self, box, ip, port):

		self.box = box
		self.ip = IPAddr6(ip) if ip.find(':') != -1 else IPAddr(ip)
		self.port = int(port)

		# self.isIpv6 = True if isinstance(ip, IPAddr6) else False
		
		self.boxRecords = BoxList()

		if isinstance(ip, IPAddr6):
			self.socket = socket(AF_INET6, SOCK_STREAM)
			self.version = 2
		else:
			self.socket = socket(AF_INET, SOCK_STREAM)
			self.version = 1

		try:
			self.socket.bind(('', self.port))
			self.msg("Listening on: %d", self.port)
		except e:
			import sys
			self.msg("Failed to bind: %d %s", self.port, e)
			sys.exit()
		self.socket.listen(100)
		threading.Thread(target=MessageManager.listen,
						args=(self, self.socket)).start()

	@staticmethod
	def listen(self, socket):
		if socket is None:
			socket = self.socket

		while True:
			clientSocket, clientAddress = socket.accept()
			threading.Thread(target=self.receive, 
				             args=(clientSocket, clientAddress)).start()
		socket.close()
	
	def createSocket(self, boxID):
		if self.version == 1:
			socketClient = socket(AF_INET, SOCK_STREAM)
		else:
			socketClient = socket(AF_INET6, SOCK_STREAM)
		socketClient.connect(('', boxID[1]))
		socketClient.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
		return socketClient
	
	def getClientBoxSocket(self, endUserAddress):
		boxID = self.boxRecords[endUserAddress]
		return createSocket(boxID) if boxID else None

	def process(self, mexp:"Mexp", clientSocket):
		switcher = {
			ACTIVATION: self.processActivation,
			ALERT: self.processAlert,
			COMPLAINT: self.processComplaint,
			FLOW: self.processFlow,
			LOOKUP: self.processLookup,
			PERMISSION: self.processPermission,
			POLICY: self.processPolicy,
			SYNC: self.processSync
		}
		func = switcher.get(mexp.tcode)
		if func is not None:
			func(mexp, clientSocket)

		# if mexp.tcode == ACTIVATION:
		# 	processActivation(mexp, clientSocket)
		# elif mexp.tcode == ALERT:
		# 	processAlert(mexp, clientSocket)
		# elif mexp.tcode == COMPLAINT:
		# 	processComplaint(mexp, clientSocket)
		# elif mexp.tcode ==  FLOW:
		# 	processFlow(mexp, clientSocket)
		# elif mexp.tcode ==  LOOKUP:
		# 	processLookup(mexp, clientSocket)
		# elif mexp.tcode ==  PERMISSION:
		# 	processPermission(mexp, clientSocket)
		# elif mexp.tcode ==  POLICY:
		# 	processPolicy(mexp, clientSocket)
		# elif mexp.tcode ==  SYNC:
		# 	processSync(mexp, clientSocket)

	def	processActivation(self, mexp:"Mexp", clientSocket):
		raise NotImplementedError("processActivation() not implemented")

	def	processAlert(self, mexp:"Mexp", clientSocket):
		raise NotImplementedError("processAlert() not implemented")

	def	processComplaint(self, mexp:"Mexp", clientSocket):
		raise NotImplementedError("processComplaint() not implemented")

	def	processFlow(self, mexp:"Mexp", clientSocket):
		raise NotImplementedError("processFlow() not implemented")

	def	processLookup(self, mexp:"Mexp", clientSocket):
		raise NotImplementedError("processLookup() not implemented")
	
	def	processPermission(self, mexp:"Mexp", clientSocket):
		raise NotImplementedError("processPermission() not implemented")
	
	def	processPolicy(self, mexp:"Mexp", clientSocket):
		raise NotImplementedError("processPolicy() not implemented")

	def	processSync(self, mexp:"Mexp", clientSocket):
		raise NotImplementedError("processSync() not implemented")
	
	def receive(self, clientSocket, clientAddress):
		data = clientSocket.recv(bufferSize)
		if not data:
			self.send(Mexp(version=self.version, tcode = 0, code=MESSAGE_ERR), clientSocket)
			return
		mexp = Mexp(raw=data)
		if not mexp.parsed:
			self.err("Mexp packet not parsed from (%s:[%s])"
					% (clientAddress[0], clientAddress[1]))
			self.send(Mexp(version=self.version, tcode = 0, code=MESSAGE_ERR), clientSocket)
			return
		self.msg("receive %s" % mexp)
		self.process(mexp, clientSocket)

	def send(self, mexp:"Mexp", socketClient):
		assert isinstance(mexp, Mexp)
		mexp.boxIP = self.ip
		self.msg("send %s" % mexp)
		try:
			socketClient.sendall(mexp.pack())
		except error as err:
			log.err("Impossible to send Mexp packet (%s, %s)", mexp, len(mexp))

	def sendAndListen(self, mexp:"Mexp", clientAddress, thread=True):
		assert isinstance(mexp, Mexp)
		clientSocket = self.createSocket(clientAddress)
		if clientSocket is None:
			self.msg("sendAndListen No Box at %s" % (clientAddress))
		else:
			self.send(mexp, clientSocket)

		if thread:
			threading.Thread(target=self.receive, 
				             args=(clientSocket, clientAddress)).start()
		else:
			self.receive(clientSocket, clientAddress)

	def msg(self, *args):
		""" Shortcut for logging """
		lg.info(*args)

	def debug(self, *args):
		""" Shortcut for logging """
		lg.debug(*args)
	
	def err(self, *args):
		""" Shortcut for logging """
		lg.error(*args)

	def warn(self, *args):
		""" Shortcut for logging """
		lg.warning(*args)

class Rmanager(MessageManager):
	def __init__(self, box, ip, port:int):
		MessageManager.__init__(self, box=box, ip=ip, port=port)

		self.zbox = None
		self.registered = False
		self._init()

	def _init(self):
		# Register your own network
		for network in self.box.networks:
			self.boxRecords[network] = (self.ip, self.port)
		# Registration process
		mexp = Mexp(version=self.version, tcode=ACTIVATION, code=ZONE_RQST, payload=ZoneRequest(version=self.version, port=self.port))
		tbox = TBox[random.randint(0, len(TBox) - 1)]
		# socketBox = self.createSocket(tbox)
		# self.send(mexp, socketBox)
		self.sendAndListen(mexp, tbox)
	
	def process(self, mexp:"Mexp", clientSocket):
		if mexp.tcode not in (ACTIVATION, ALERT, LOOKUP, PERMISSION, POLICY, FLOW):
			self.debug("Rbox does not manage %s tcode message %s" % mexp.tcode)
			return
		MessageManager.process(self, mexp, clientSocket)

	def lookupBox(self, network):
		boxID = self.boxRecords[network]
		if boxID is not None:
			return boxID
		else:
			mexp = Mexp(version=self.version, tcode=LOOKUP, code=LOOKUP_RQST, payload=LookupRequest(userIP=network))
			self.sendAndListen(mexp=mexp, clientAddress=self.zbox, thread=False)
			return self.boxRecords[network]

	def	processActivation(self, mexp:"Mexp", clientSocket):
		self.debug("Rbox processActivation  (%s, %s)", mexp.tcode, mexp.code)
		if mexp.code == ZONE_RPLY:
			if not mexp.payload.parsed:
				self.err("Rbox can't parse (%s, %s)", mexp.tcode, mexp.code)
			else:
				networks = []
				netmasks = []
				for net in self.box.networks:
					networks.append(net[0])
					netmasks.append(net[1])
				
				self.zbox = (mexp.payload.boxIP, mexp.payload.port)
				mexpReply = Mexp(version=mexp.version, tcode=mexp.tcode, code=REG_RQST, mid=mexp.mid+1, payload=RegistrationRequest(version=mexp.version, port=self.port, networks=networks, netmasks=netmasks))
				clientSocket.close()
				# self.debug("processActivation: %s" % (self.zbox,))
				# socketBox = self.createSocket(self.zbox)
				self.sendAndListen(mexpReply, self.zbox)
		elif mexp.code == REG_RPLY:
			if not mexp.payload.parsed:
				self.err("Rbox can't parse (%s, %s)", mexp.tcode, mexp.code)
			else:
				if mexp.payload.decision:
					self.registered = True
				else:
					import sys
					self.err("Zbox refused the registration of the Rbox")
					sys.exit()

	def	processAlert(self, mexp:"Mexp", clientSocket):
		if   mexp.code == ALERT_NOTIF:
			if not mexp.payload.parsed:
				self.debug("Rbox can't parse (%s, %s)", mexp.tcode, mexp.code)
			else:
				code = self.box.getAlertNotification(mexp.payload)
				if  code == ALERT_ACK:
					mexpReply = Mexp(version=mexp.version, tcode=mexp.tcode, code=ALERT_ACK, mid=mexp.mid+1)
					self.send(mexpReply, clientSocket)
				elif  code == COMPLAINT_RQST:
					mexp = Mexp(version=self.version, tcode=COMPLAINT, code=COMPLAINT_RQST, payload=ComplaintRequest(version=self.messageManager.version, boxIP=mexp.boxIP))
					self.sendAndListen(mexp, zbox)
		elif mexp.code == ALERT_ACK:
			# Save the flowheader for now to check if the traffic is really stop if not send COMPLAINT
			pass
		elif mexp.code == ALERT_BRDT_RPLY:
			# Save the flowheader for now to check if the traffic is really stop if not send COMPLAINT
			pass
		elif mexp.code == ALERT_DL_BRDT_RQST:
			if not mexp.payload.parsed:
				self.msg("Rbox can't parse (%s, %s)", mexp.tcode, mexp.code)
			else:
				self.box.getAlertBroadcast(mexp.payload)
				mexpReply = Mexp(version=mexp.version, tcode=mexp.tcode, code=ALERT_DL_BRDT_RPLY, mid=mexp.mid+1)
				self.send(mexpReply, clientSocket)
	
	def	processLookup(self, mexp:"Mexp", clientSocket) -> None:
		if mexp.code == LOOKUP_RPLY:
			if not mexp.payload.parsed:
				self.err("Rbox can't parse (%s, %s)", mexp.tcode, mexp.code)
			else:
				if mexp.payload.boxIP != IP_ANY and mexp.payload.boxIP != IPAddr6.UNDEFINED:
					self.boxRecords[(mexp.payload.network, mexp.payload.netmask)] = (mexp.payload.boxIP, mexp.payload.port)
	
	def	processPermission(self, mexp:"Mexp", clientSocket):
		if mexp.code == PERMISSION_RQST:
			if not mexp.payload.parsed:
				self.err("Rbox can't parse (%s, %s)", mexp.tcode, mexp.code)
			else:
				permReply = self.box.getPermissionRequest(mexp.payload)
				mexpReply = Mexp(version=mexp.version, tcode=mexp.tcode, code=PERMISSION_RPLY, mid=mexp.mid+1, payload=permReply)
				self.send(mexpReply, clientSocket)
		elif  mexp.code == PERMISSION_RPLY:
			if not mexp.payload.parsed:
				self.err("Rbox can't parse (%s, %s)", mexp.tcode, mexp.code)
			else:
				self.box.getPermissionReply(mexp.mid -1, mexp.payload)

	def	processPolicy(self, mexp:"Mexp", clientSocket):
		raise NotImplementedError("processPolicy() not implemented")
	
	def	processFlow(self, mexp:"Mexp", clientSocket):
		raise NotImplementedError("processFlow() not implemented")

	def	processComplaint(self, mexp:"Mexp", clientSocket):
		if   mexp.code == COMPLAINT_INQ:
			if not mexp.payload.parsed:
				self.debug("Rbox can't parse (%s, %s)", mexp.tcode, mexp.code)
			else:
				code, cplReply  = self.box.getComplaintInquery(mexp.payload)
				mexpReply = Mexp(version=mexp.version, tcode=mexp.tcode, code=COMPLAINT_RPLY, mid=mexp.mid+1)
	
	def createMessage(self, event, tcode:int, code:int, payload:"packet_base", dstIP, listen=True):
		mexp = Mexp(version=self.version, tcode=tcode, code=code, payload=payload)
		self.box.setEvent(event, mexp.mid)
		boxID = self.lookupBox(dstIP)
		if boxID is None:
			self.err("createMessage No Box for %s" % (dstIP))
			return
		if listen:
			self.sendAndListen(mexp, boxID)
		else:
			self.send(mexp, self.createSocket(boxID))

class Zmanager(MessageManager):
	def __init__(self, box, ip, port):
		self.debug("__init__ ip=%s port=%s" % (ip, port))
		MessageManager.__init__(self,  box=box, ip=ip, port=port)

		self.networks = set()
		self.online = False
		self.zBoxRecords = BoxList()

	def process(self, mexp:"Mexp", clientSocket):
		if mexp.tcode not in (ACTIVATION, ALERT, COMPLAINT, LOOKUP):
			self.err("Zbox does not manage (%s, %s) message %s" % (mexp.tcode, mexp.code))
			return
		MessageManager.process(self, mexp, clientSocket)

	def _networkExists(self, network:"IPv4/Ipv6"):
		self.debug("Zbox networkExists (%s, %s)" % (network, self.networks))
		return network in self.networks
	
	def lookupBox(self, network:"IPv4/Ipv6") -> ("IPv4/Ipv6", int):
		boxID = self.boxRecords[network]
		if boxID is not None:
			return boxID
		else:
			zbox = self.zBoxRecords[network]
			if zbox is not None:
				mexp = Mexp(version=self.version, tcode=LOOKUP, code=LOOKUP_DL_RQST, payload=LookupDelegateRequest(userIP=network))
				self.sendAndListen(mexp=mexp, clientAddress=zbox, thread=False)
				self.debug("Zbox lookupBox (%s, %s)" % (network, self.boxRecords[network]))
				return self.boxRecords[network]
			else:
				mexp = Mexp(version=self.version, tcode=LOOKUP, code=LOOKUP_RQST, payload=LookupRequest(userIP=network))
				tbox = TBox[random.randint(0, len(TBox) - 1)]
				self.sendAndListen(mexp=mexp, clientAddress=tbox, thread=False)
				return self.lookupBox(network)

	def broadcastAlert(self, senderBox, alertMsg:"AlertDelegateBrdcRqst") -> None:
		self.debug("Zmanager broadcastAlert: %s %s", senderBox, alertMsg)
		for network in list(self.boxRecords):
			boxID = self.boxRecords[network]
			self.debug("broadcastAlert boxID: %s", boxID)	
			if not boxID[0] == senderBox and not alertMsg.sip.in_network(network):
				mexp = Mexp(version=self.version, tcode=ALERT, code= ALERT_DL_BRDT_RQST, payload=alertMsg)
				self.sendAndListen(mexp, boxID)

	def	processActivation(self, mexp:"Mexp", clientSocket):
		if mexp.code == REG_RQST:
			# regPly = RegistrationReply(decision=True)
			if not mexp.payload.parsed :
				self.err("Zbox can't parse (%s, %s)" % (mexp.tcode, mexp.code))
			else:
				for net, mask in zip(mexp.payload.networks, mexp.payload.netmasks):
					if self._networkExists((net, mask)):
						regPly = RegistrationReply(version=mexp.version, decision=False)
						mexpReply = Mexp(version=mexp.version, tcode=mexp.tcode, code=REG_RPLY, mid=mexp.mid+1, payload=regPly)
						self.send(mexpReply, clientSocket)
						return
				for net, mask in zip(mexp.payload.networks, mexp.payload.netmasks):
					self.boxRecords[(net, mask)] = (mexp.boxIP, mexp.payload.port)
					self.networks.add((net, mask))
				regPly = RegistrationReply(version=mexp.version, decision=True)
				mexpReply = Mexp(version=mexp.version, tcode=mexp.tcode, code=REG_RPLY, mid=mexp.mid+1, payload=regPly)
				self.send(mexpReply, clientSocket)
		else:
			self.err("Zbox does not manage code message %s" % mexp.code)

	def	processAlert(self, mexp:"Mexp", clientSocket):
		if 	 mexp.code == ALERT_BRDT_RQST:
			if not mexp.payload.parsed:
				self.err("Rbox can't parse (%s, %s)", mexp.tcode, mexp.code)
			else:
				mexpReply = Mexp(version=mexp.version, tcode=mexp.tcode, code=ALERT_BRDT_RPLY, mid=mexp.mid+1)
				self.send(mexpReply, clientSocket)
				self.broadcastAlert(mexp.boxIP, mexp.payload)
		elif mexp.code == ALERT_BRDT_RPLY:
			# Save the flowheader for now to check if the traffic is really stop if not send COMPLAINT
			pass
	
	def	processComplaint(self, mexp:"Mexp", clientSocket):
		pass
	
	def	processLookup(self, mexp:"Mexp", clientSocket):
		if   mexp.code == LOOKUP_RQST:
			if not mexp.payload.parsed:
				self.err("Zbox can't parse (%s, %s)", mexp.tcode, mexp.code)
			else:
				boxID 		= self.lookupBox(mexp.payload.userIP)
				mexpReply 	= None
				if boxID is not None:
					net, mask = self.boxRecords.getNetwork(boxID)	
					mexpReply 	= Mexp(version=mexp.version, tcode=mexp.tcode, code=LOOKUP_RPLY, mid=mexp.mid+1, payload=LookupReply(version=mexp.version, network=net, netmask=mask, boxIP=boxID[0], port=boxID[1]))
				else:
					mexpReply 	= Mexp(version=mexp.version, tcode=mexp.tcode, code=LOOKUP_RPLY, mid=mexp.mid+1, payload=LookupReply(version=mexp.version))
				self.send(mexpReply, clientSocket)
		elif mexp.code == LOOKUP_DL_RQST:
			if not mexp.payload.parsed:
				self.err("Zbox can't parse (%s, %s)", mexp.tcode, mexp.code)
			else:
				boxID 		= self.lookupBox(mexp.payload.userIP)
				self.debug("Zbox Message %s and BoxID %s" % (mexp.code, boxID))
				mexpReply 	= None
				if boxID is not None:
					net, mask = self.boxRecords.getNetwork(boxID)	
					mexpReply 	= Mexp(version=mexp.version, tcode=mexp.tcode, code=LOOKUP_DL_RPLY, mid=mexp.mid+1, payload=LookupDelegateReply(version=mexp.version, network=net, netmask=mask, boxIP=boxID[0], port=boxID[1]))
				else:
					mexpReply 	= Mexp(version=mexp.version, tcode=mexp.tcode, code=LOOKUP_DL_RPLY, mid=mexp.mid+1, payload=LookupDelegateReply(version=mexp.version))
				self.send(mexpReply, clientSocket)
		elif mexp.code == LOOKUP_RPLY:
			if not mexp.payload.parsed:
				self.err("Rbox can't parse (%s, %s)", mexp.tcode, mexp.code)
			else:
				self.zBoxRecords[(mexp.payload.network, mexp.payload.netmask)] = (mexp.payload.boxIP, mexp.payload.port)
		elif mexp.code == LOOKUP_DL_RPLY:
			if not mexp.payload.parsed:
				self.err("Rbox can't parse (%s, %s)", mexp.tcode, mexp.code)
			else:
				self.boxRecords[(mexp.payload.network, mexp.payload.netmask)] = (mexp.payload.boxIP, mexp.payload.port)

class Tmanager(MessageManager):
	def __init__(self, box, ip, port, version, filename):
		MessageManager.__init__(self,  box=box, ip=ip, port=port)
		
		self.debug("Tmanager listen on: %d", self.port)
		self.networks = []
		self.online = False

		self._init(version, filename)

	def _init(self, version, filename):
		self.debug("Tmanager init: %s %s", version, filename)
		if filename is None:
			filename = "pox/boxes/config/tbox.conf"
		
		with open (filename, 'r') as file:
			address = yaml.safe_load(file)
			for ip in address["ip"]:
				if ip["version"] == 4 and int(version) == 4:
					for data in ip["records"]:
						for net in data["networks"]:
							self.boxRecords[IPAddr.parse_cidr(net)] = (IPAddr(data["box_ip"]), int(data["port"]))
					break
				elif ip["version"] == 6 and int(version) == 6:
					for data in ip["records"]:
						for net in data["networks"]:
							self.boxRecords[IPAddr6.parse_cidr(net)] = (IPAddr6(data["box_ip"]), int(data["port"]))
					break
				else:
					import sys
					self.err("Tbox does not manage %s version" % (version))
					sys.exit(1)
	
	def process(self, mexp:"Mexp", clientSocket):
		if mexp.tcode not in (ACTIVATION, ALERT, LOOKUP, SYNC):
			self.err("Tbox does not manage (%s, %s)  message" % (mexp.tcode, mexp.code))
			return
		MessageManager.process(self, mexp, clientSocket)

	def	processActivation(self, mexp:"Mexp", clientSocket):
		if mexp.code == ZONE_RQST:
			if not mexp.payload.parsed :
				self.err("Rbox can't parse (%s, %s)" % (mexp.tcode, mexp.code))
			else:
				boxID = self.boxRecords[mexp.boxIP]
				# for net in mexp.payload.networks:
				# 	current = self.boxRecords[net]
				# 	if current is not None:
				# 		if boxID is None:
				# 			boxID = current
				# 		elif boxID != current:
				# 			boxID = None
				# 			break
				# 	else:
				# 		boxID = None
				# 		break
				self.err("processActivation %s" % (boxID,))
				if boxID is None:
					regPly = ZoneReply(version=mexp.version)
				else:
					regPly = ZoneReply(version=mexp.version, boxIP=boxID[0], port=boxID[1])
				mexpReply = Mexp(version=mexp.version, tcode=mexp.tcode, code=ZONE_RPLY, mid=mexp.mid+1, payload=regPly)
				self.send(mexpReply, clientSocket)
		else:
			self.err("processActivation mexp tcode %s error" % (mexp.code,))

	def	processLookup(self, mexp:"Mexp", clientSocket):
		if mexp.code == LOOKUP_RQST :
			if not mexp.payload.parsed:
				self.err("Tbox can't parse (%s, %s)", mexp.tcode, mexp.code)
			else:
				boxID 	= self.boxRecords[mexp.payload.userIP]
				net, mask = self.boxRecords.getNetwork(boxID)
				mexpReply = Mexp(version=mexp.version, tcode=mexp.tcode, code=LOOKUP_RPLY, mid=mexp.mid+1, payload=LookupReply(version=mexp.version, network=net, netmask=mask, boxIP=boxID[0], port=boxID[1]))
				self.send(mexpReply, clientSocket)
	
	def	processAlert(self, mexp:"Mexp", clientSocket):
		pass
	
	def	processComplaint(self, mexp:"Mexp", clientSocket):
		pass
	
	def	processSync(self, mexp:"Mexp", clientSocket):
		pass
