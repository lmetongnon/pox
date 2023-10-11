import logging
import pox.openflow.libopenflow_01 as of

from pox.boxes.utils.tools import Permission, Policy, Alert
from pox.boxes.utils.flow import FlowHeader
log = logging.getLogger('list')

from pox.lib.addresses import IPAddr, IPAddr6

from queue import PriorityQueue
import time, copy

class List(object):
	def __init__(self):
		self.records = {}

	def add(self, key, value) -> None:
		self.records[key] = value

	def delete(self, key) -> object:
		return self.records.pop(key, None)

	def exists(self, key) -> bool:
		return key in self.records

	def update(self, records) -> None:
		self.records.update(records)

	def keys(self) -> object:
		return self.records.keys()

	def values(self) -> [object]:
		return [self[key] for key in self.keys()]
	
	def items(self) -> "view":
		return self.records.items()

	def __len__(self) -> int:
		return self.records.__len__()

	def __iter__(self):
		return self.records.__iter__()

	def __getitem__(self, key) -> object :
		return self.records.get(key, None)
  
	def __setitem__(self, key, value) -> None:
		self.records.__setitem__(key, value)

	def __delitem__(self, key) -> None:
		self.records.__delitem__(key)

	def __contains__(self, key) -> bool:
		return self.exists(key)

	def __str__(self) -> str:
		return self.records.__str__()

	def __repr__(self) -> str:
		return self.__str__()

	def info(self, *args) -> None:
		""" Shortcut for logging """
		log.info(*args)
	
	def debug(self, *args) -> None:
		""" Shortcut for logging """
		log.debug(*args)
	
	def err(self, *args) -> None:
		""" Shortcut for logging """
		log.error(*args)

	def warn(self, *args) -> None:
		""" Shortcut for logging """
		log.warning(*args)

class BoxList(List):
	'''
        The box list contained a map to access the a box managing a network. You can add new tuples (IP network - Box IP) and query them when needed
    '''
	def __init__(self):
		List.__init__(self)

	def add(self, networks:"(IPAddr/IPAddr6, int)", boxID:"IPAddr/IPAddr6"):
		"""
		Adds the link (network - BoxID) to the list 

		@type networks: IPAddr/IPAddr6
		@param networks: The networks manage by the box
		@type boxID: tuple(IPAddr/IPAddr6, int)
		@param boxID: The box identity (address, port)

		@rtype: None
		@return: None
		"""
		self.info("add len: %d" % len(List.keys(self)))
		if not isinstance(boxID, tuple):
			self.err("add %s" % boxID)
			return
		if isinstance(networks, list):
			for network in networks:
				self._check(network, boxID[0])
			for network in networks:
				List.add(self, network, boxID)
		else:
			self._check(networks, boxID[0])
			List.add(self, networks, boxID)
	
	def values(self) -> ["IPAddr/IPAddr6"]:
		"""
		Return a list of the network present in this list 

		@rtype: list
		@return: The list of all box ID as a list
		"""
		return [self[key] for key, _ in self.keys()]

	def _check(self, network:"(IPAddr/IPAddr6, int)", boxIP:"IPAddr/IPAddr6"):
		"""
		Check that an Ipv4 network is protect by an IPv4 Box and we have no mix 

		@type network: IPAddr/IPAddr6
		@param network: The networks IP
		@type boxID: tuple(IPAddr/IPAddr6, int)
		@param boxID: The box identity (address, port)

		@rtype: None
		@return: None
		"""
		self.info("_check : %s %s" % (network, boxIP))
		if isinstance(boxIP, IPAddr) and not isinstance(network, IPAddr):
			self.info("network address %s is not ipv4" % network)
			return
		elif isinstance(boxIP, IPAddr6) and not isinstance(network, IPAddr6):
			self.info("network address %s is not ipv6" % network)
			return

	def exists(self, network):
		"""
		Check that a network is present inside the box list

		@type network: IPAddr/IPAddr6
		@param network: The networks IP

		@rtype: bool
		@return: If the network is presents
		"""
		if List.exists(self, network):
			return True
		for net in List.keys(self):
			if network.in_network(net):
				return True
		return False

	def __getitem__(self, network):
		self.info("__getitem__ len: %d" % len(List.keys(self)))
		if List.exists(self, network):
			return List.__getitem__(self, network)
		for net in List.keys(self):
			self.info("__getitem__ %s" % (net,))
			if network.in_network(net):
				return List.__getitem__(self, net)
		return None

	def __setitem__(self, networks, boxID):
		self.info("__setitem__ len: %d" % len(List.keys(self)))
		if not isinstance(boxID, tuple):
			self.err("__setitem__ %s" % boxID)
			return
		# if isinstance(networks, list):
		# 	for network in networks:
		# 		self._check(network, boxID[0])
		# 	for network in networks:
		# 		List[network] = boxID
		# else:
		self._check(networks[0], boxID[0])
		List.__setitem__(self, networks, boxID)
		self.info("__setitem__ after len: %d" % len(List.keys(self)))

	def getNetwork(self, BoxID):
		for net in List.keys(self):
			if self.__getitem__(net) == BoxID:
				return net
		return None, None

class PermissionList(List):
	'''
        The permission list contained a map to access a flow and its permission. A flow is ID by its header
    '''
	def __init__(self):
		List.__init__(self)

	def add(self, flowHeader, permission, bidirectionnal=True):
		if not isinstance(flowHeader, FlowHeader) or not isinstance(permission, Permission):
			self.err("add %s %s" % flowHeader, permission)
			return
		List.add(self, flowHeader, permission)
		if bidirectionnal:
			List.add(self, flowHeader.flip(), copy.deepcopy(permission))

	def delete(self, flowHeader) -> object:
		if not isinstance(flowHeader, FlowHeader):
			self.err("delete %s" % flowHeader)
			return
		return List.delete(self, flowHeader)


	def expire(self, flowHeader, bidirectionnal=True) -> object:
		self.debug("expire flowheader: %s list: %s " % (flowHeader, self))
		import time
		if not isinstance(flowHeader, FlowHeader):
			self.err("expire %s" % flowHeader)
			return
		stop = time.time()
		if not bidirectionnal:
			permission = List.__getitem__(self, flowHeader)
			permission.stop = stop
		else:
			permission = List.__getitem__(self, flowHeader)
			permission.stop = stop
			permission = List.__getitem__(self, flowHeader.flip())
			permission.stop = stop
	
	def __getitem__(self, flowHeader):
		return List.__getitem__(self, flowHeader)

	def __setitem__(self, flowHeader, permission):
		if not isinstance(flowHeader, FlowHeader) or not isinstance(permission, Permission):
			self.err("__setitem__ %s %s" % flowHeader, permission)
		List.__setitem__(self, flowHeader, permission)

	def __contains__(self, flowHeader):
		if not isinstance(flowHeader, FlowHeader):
			self.err("__contains__ %s %s" % flowHeader)
		return List.__contains__(self, flowHeader)

	def check(self) -> None :
		"""
		We check the list of permission with the current time to remove expired device's permission 
		"""
		for key in list(self.keys()):
			self.debug("PermissionList check key: %s " % (key))
			self.debug("PermissionList check key: %s elasped: %d duration: %d" % (key, (time.time() - self.__getitem__(key).timestamp), self.__getitem__(key).duration))
			if (time.time() - self.__getitem__(key).stop) >= 0:
				self.delete(key)

class FlowList(object):
	'''
        The flow list contained information related to an device and all its communication. We also have this same device with the same communication but organize with specific flow header 
    '''
	def __init__(self, timeout = -1):
		self.timestamp = time.time()
		self.timeout = timeout
		self.ipSet = dict()	# sip => dip => set(dport) all flow from/to the device
		self.ipFlows = dict() # ip => flowheader => flow, all the flowheader to the device and the corresponding flow

	def updateSet(self, sip, dip, dport:int):
		if sip not in self.ipSet:
			self.ipSet[sip] = List()
		if dip not in self.ipSet[sip]:
			self.ipSet[sip][dip] = set()
		self.ipSet[sip][dip].add(dport)

	def updateFlow(self, sip, flow:"Flow"):
		if not isinstance(flow, of.ofp_flow_stats):
			return
		if sip not in self.ipFlows:
			self.ipFlows[sip] = List()
		flowheader = FlowHeader.fromMatch(flow.match)
		if flowheader not in self.ipFlows[sip]:
			self.ipFlows[sip][flowheader] = flow
	
	def __str__(self):
		outstr ='[ timestamp: '
		outstr += str(self.timestamp)+" set: "
		outstr += str(self.ipSet)+" flow: "
		for ip in self.ipFlows:
			for flh in self.ipFlows[ip]:
				outstr += str(flh)+" "
				outstr += self.ipFlows[ip][flh].show()+"\n"
		outstr+=']'
		return outstr 

	def add(self, ip, flow:"Flow"):
		# if not isinstance(flow, Flow):
		# 	self.err("add flow is not a Flow instance")
		# 	return
		if not ipSet[ip]:
			self.ipSet[ip] = set()
		# if self.ipSet[ip]:

class BlackList(object):

	def __init__(self):
		self.set = set()
		self.queue = PriorityQueue()

	def add(self, timestamp, addr) -> None:
		self.set.add(addr)
		self.queue.put((timestamp, addr))

	def __contains__(self, addr) -> bool:
		return addr in self.set

	def check(self) -> None:
		while not self.queue.empty():
			pair = self.queue.get()
			log.debug("BlackList check Address: %s Priority: %s" % (pair[1], pair [0]))
			if time.time() < pair[0]:
				self.queue.put(pair)
				return
			self.set.remove(pair[1])

class AlertList(List):
	
	def check(self, box) -> None :
		"""
		We check the list of the alert and started mitigation process
		"""
		for address in list(self.keys()):
			alert = self.delete(address)
			self.debug("AlertList check address: %s alert: %s" % (address, alert))
			myDevice = box.isOurDevice(address)
			self.debug("address %s and mydevice: %s" % (address, box.isOurDevice(address)))
			if isinstance(alert.flowHeader, list):
				for flowHeader, flow in zip(alert.flowHeader, alert.flow):
					box.mitigation.process(myDevice=myDevice, alert=Alert(alert.type, flowHeader, flow))
					if flowHeader in box.permissionList:
						box.permissionList.expire(flowHeader)
			else:
				box.mitigation.process(myDevice=myDevice, alert=alert)
				if alert.flowHeader in box.permissionList:
					box.permissionList.expire(alert.flowHeader)

class PolicyList(List):
	def __getitem__(self, address) -> object :
		obj = self.records.get(address, None)
		if obj is None:
			return Policy(address)
		return obj