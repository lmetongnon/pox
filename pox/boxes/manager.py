import logging
lg = logging.getLogger('manager')

import random
import threading
import time
import yaml

# from abc import ABC
from pox.lib.addresses import IPAddr, IPAddr6
from pox.boxes.proto.mexp import Mexp
from pox.boxes.utils.mylist import BoxList

from pox.boxes.proto.activation import ZoneRequest, ZoneReply, RegistrationRequest, RegistrationReply
from pox.boxes.proto.mexp import ACTIVATION, ALERT, LOOKUP, PERMISSION, POLICY, FLOW, SYNC, COMPLAINT
from pox.boxes.proto.mexp import ZONE_RQST, ZONE_RPLY, REG_RQST, REG_RPLY, MESSAGE_ERR, PERMISSION_RQST, PERMISSION_RPLY

from socket import *

bufferSize = 4096
TBox = [('', 15700)]
class MessageManager(object):
	"""
	Class managing message exchange between the boxes
	"""
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
	
	def isBoxRecorded(self, mexp):
		# TODO mexp decrypted
		return mexp.boxIP in self.boxRecords.value()

	def lookupBox(self, network):
		return boxRecords.get(network)

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

	def process(self, mexp, clientSocket):
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

	def	processActivation(self, mexp, clientSocket):
		raise NotImplementedError("processActivation() not implemented")

	def	processAlert(self, mexp, clientSocket):
		raise NotImplementedError("processAlert() not implemented")

	def	processComplaint(self, mexp, clientSocket):
		raise NotImplementedError("processComplaint() not implemented")

	def	processFlow(self, mexp, clientSocket):
		raise NotImplementedError("processFlow() not implemented")

	def	processLookup(self, mexp, clientSocket):
		raise NotImplementedError("processLookup() not implemented")
	
	def	processPermission(self, mexp, clientSocket):
		raise NotImplementedError("processPermission() not implemented")
	
	def	processPolicy(self, mexp, clientSocket):
		raise NotImplementedError("processPolicy() not implemented")

	def	processSync(self, mexp, clientSocket):
		raise NotImplementedError("processSync() not implemented")
	
	def receive(self, clientSocket, clientAddress):
		data = clientSocket.recv(bufferSize)
		if not data:
			self.send(Mexp(version=self.version, tcode = 0, code=MESSAGE_ERR, boxIP=self.ip), clientSocket)
			return
		mexp = Mexp(raw=data)
		if not mexp.parsed:
			self.err("Mexp packet not parsed from (%s:[%s])"
					% (clientAddress[0], clientAddress[1]))
			self.send(Mexp(version=self.version, tcode = 0, code=MESSAGE_ERR, boxIP=self.ip), clientSocket)
			return
		self.msg("receive %s" % mexp)
		self.process(mexp, clientSocket)

	def send(self, mexp, socketClient):
		assert isinstance(mexp, Mexp)
		mexp.boxIP = self.ip
		self.msg("send %s" % mexp)
		try:
			socketClient.sendall(mexp.pack())
		except error as err:
			log.err("Impossible to send Mexp packet (%s, %s)", mexp, len(mexp))

	def sendAndListen(self, mexp, clientAddress, thread=True):
		clientSocket = self.createSocket(clientAddress)
		if clientSocket is None:
			#Lookup
			pass
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

	def err(self, *args):
		""" Shortcut for logging """
		lg.error(*args)

	def warn(self, *args):
		""" Shortcut for logging """
		lg.warning(*args)

	# def __str__(self):
	# 	if hasattr(self, "_to_str"):
	# 		try:
	# 			return self._to_str()
	# 		except Exception as e:
	# 			#import traceback
	# 			#traceback.print_exc()
	# 			lg.debug("str(%s): %s" % (self.__class__.__name__, e))
	# 		return "[%s:Bad representation]" % (self.__class__.__name__,)
	# 	return "[%s l:%i%s]" % (self.__class__.__name__, len(self),
	# 		"" if self.next else " *")

class Rmanager(MessageManager):
	def __init__(self, box, ip, port):
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
	
	def process(self, mexp, clientSocket):
		if mexp.tcode not in (ACTIVATION, ALERT, LOOKUP, PERMISSION, POLICY, FLOW):
			self.msg("Rbox does not manage %s tcode message %s" % mexp.tcode)
			return
		MessageManager.process(self, mexp, clientSocket)

	def	processActivation(self, mexp, clientSocket):
		self.msg("Rbox processActivation  (%s, %s)", mexp.tcode, mexp.code)
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
				# self.msg("processActivation: %s" % (self.zbox,))
				# socketBox = self.createSocket(self.zbox)
				self.sendAndListen(mexpReply, self.zbox)
		elif mexp.code == REG_RPLY:
			if not mexp.payload.parsed:
				self.err("Rbox can't parse (%s, %s)", mexp.tcode, mexp.code)
			else:
				if mexp.payload.decision:
					self.registered = True
				else:
					self.err("Zbox refused the registration of the Rbox")
					return

	def	processAlert(self, mexp, clientSocket):
		pass
	
	def	processLookup(self, mexp, clientSocket):
		pass
	
	def	processPermission(self, mexp, clientSocket):
		if mexp.code == PERMISSION_RQST:
			if not mexp.payload.parsed:
				self.msg("Rbox can't parse (%s, %s)", mexp.tcode, mexp.code)
			else:
				permReply = self.box.requestPermission(mexp.payload)
				mexpReply = Mexp(version=mexp.version, tcode=mexp.tcode, code=PERMISSION_RPLY, mid=mexp.mid+1, payload=permReply)
				self.send(mexpReply, clientSocket)
		elif  mexp.code == PERMISSION_RPLY:
			if not mexp.payload.parsed:
				self.msg("Rbox can't parse (%s, %s)", mexp.tcode, mexp.code)
			else:
				self.box.replyPermission(mexp)
				# return True

	def	processPolicy(self, mexp, clientSocket):
		pass
	
	def	processFlow(self, mexp, clientSocket):
		pass

	def createMessage(self, event, tcode, code, payload, dstIP, listen=True):
		mexp = Mexp(version=self.version, tcode=tcode, code=code, payload=payload)
		self.box.setEvent(event, mexp.mid)
		boxID = self.boxRecords[dstIP]
		if boxID is None:
			# Lookup
			self.msg("createMessage need Lookup for Box of %s" % (dstIP))
			return
		if listen:
			self.sendAndListen(mexp, boxID)
		else:
			self.send(mexp, self.createSocket(boxID))

class Zmanager(MessageManager):
	def __init__(self, box, ip, port):
		self.msg("__init__ ip=%s port=%s" % (ip, port))
		MessageManager.__init__(self,  box=box, ip=ip, port=port)

		self.networks = set()
		self.online = False

	def process(self, mexp, clientSocket):
		if mexp.tcode not in (ACTIVATION, ALERT, COMPLAINT, LOOKUP):
			self.msg("Zbox does not manage (%s, %s) message %s" % (mexp.tcode, mexp.code))
			return
		MessageManager.process(self, mexp, clientSocket)

	def check(self, network):
		self.msg("Zbox check (%s, %s)" % (network, self.networks))
		return network in self.networks
	
	def	processActivation(self, mexp, clientSocket):
		if mexp.code == REG_RQST:
			# regPly = RegistrationReply(decision=True)
			if not mexp.payload.parsed :
				self.msg("Zbox can't parse (%s, %s)" % (mexp.tcode, mexp.code))
			else:
				for net, mask in zip(mexp.payload.networks, mexp.payload.netmasks):
					if self.check((net, mask)):
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
			self.msg("Zbox does not manage code message %s" % mexp.code)


	def	processAlert(self, mexp, clientSocket):
		pass
	
	def	processComplaint(self, mexp, clientSocket):
		pass
	
	def	processLookup(self, mexp, clientSocket):
		pass

class Tmanager(MessageManager):
	def __init__(self, box, ip, port):
		MessageManager.__init__(self,  box=box, ip=ip, port=port)
		
		self.msg("Tmanager on: %d", self.port)
		self.networks = []
		self.online = False

		self._init()

	def _init(self, filename = None):
		if filename is None:
			filename = "pox/boxes/config/tbox.conf"
			# 2000:db8::/32,2000:db8::1:1,15000
		
		with open (filename, 'r') as file:
			data = yaml.safe_load(file)
			if data["version"] == 4:
				for info in data["records"]:
					self.boxRecords[IPAddr.parse_cidr(info["network"])] = (IPAddr(info["ip"]), int(info["port"]))
			elif data["version"] == 6:
				for info in data[records]:
					self.boxRecords[IPAddr.parse_cidr(info["network"])] = (IPAddr(info["ip"]), int(info["port"]))
			# for line in file:
			# 	self.msg("_init %s" % line)
			# 	words = line.split(',')
			# 	self.networks.append(
			# 		IPAddr6.parse_cidr(words[0])
			# 	)
			# 	# self.boxRecords.add(
			# 	# 	networks=IPAddr6.parse_cidr(words[0]), 
			# 	# 	boxID=[IPAddr6(words[1]), int(words[2])]
			# 	# )
				# self.boxRecords[IPAddr6.parse_cidr(words[0])] = (IPAddr6(words[1]), int(words[2]))
	
	def process(self, mexp, clientSocket):
		if mexp.tcode not in (ACTIVATION, ALERT, LOOKUP, SYNC):
			self.msg("Tbox does not manage (%s, %s)  message" % (mexp.tcode, mexp.code))
			return
		MessageManager.process(self, mexp, clientSocket)

	def	processActivation(self, mexp, clientSocket):
		if mexp.code == ZONE_RQST:
			if not mexp.payload.parsed :
				self.msg("Rbox can't parse (%s, %s)" % (mexp.tcode, mexp.code))
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
				self.msg("processActivation %s" % (boxID,))
				if boxID is None:
					regPly = ZoneReply(version=mexp.version)
				else:
					regPly = ZoneReply(version=mexp.version, boxIP=boxID[0], port=boxID[1])
				mexpReply = Mexp(version=mexp.version, tcode=mexp.tcode, code=ZONE_RPLY, mid=mexp.mid+1, payload=regPly)
				self.send(mexpReply, clientSocket)
		else:
			self.err("processActivation mexp tcode %s error" % (mexp.code,))

	def	processAlert(self, mexp, clientSocket):
		pass
	
	def	processComplaint(self, mexp, clientSocket):
		pass
	
	def	processSync(self, mexp, clientSocket):
		pass
