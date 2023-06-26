import logging
import pox.openflow.libopenflow_01 as of

from pox.boxes.utils.tools import Permission
from pox.boxes.utils.flow import FlowHeader
lg = logging.getLogger('list')

from pox.lib.addresses import IPAddr, IPAddr6

import time

class List(object):
	def __init__(self):
		self.records = {}

	def add(self, key, value) -> None:
		self.records[key] = value

	def delete(self, key):
		self.records.pop(key, None)

	def exists(self, key):
		return key in self.records

	def update(self, records):
		self.records.update(records)

	def keys(self):
		return self.records.keys()

	def values(self):
		return [self[key] for key in self.keys()]

	def __len__(self):
		return self.records.__len__()

	def __iter__(self):
		return self.records.__iter__()

	def __getitem__(self, key):
		return self.records.get(key, None)
  
	def __setitem__(self, key, value):
		self.records.__setitem__(key, value)

	def __contains__(self, key):
		return self.exists(key)

	def __str__(self):
		return self.records.__str__()

	def msg(self, *args):
		""" Shortcut for logging """
		lg.info(*args)

	def err(self, *args):
		""" Shortcut for logging """
		lg.error(*args)

	def warn(self, *args):
		""" Shortcut for logging """
		lg.warning(*args)

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
		self.msg("add len: %d" % len(List.keys(self)))
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
		self.msg("_check : %s %s" % (network, boxIP))
		if isinstance(boxIP, IPAddr) and not isinstance(network, IPAddr):
			self.msg("network address %s is not ipv4" % network)
			return
		elif isinstance(boxIP, IPAddr6) and not isinstance(network, IPAddr6):
			self.msg("network address %s is not ipv6" % network)
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
		self.msg("__getitem__ len: %d" % len(List.keys(self)))
		if List.exists(self, network):
			return List.__getitem__(self, network)
		for net in List.keys(self):
			self.msg("__getitem__ %s" % (net,))
			if network.in_network(net):
				return List.__getitem__(self, net)
		return None

	def __setitem__(self, networks, boxID):
		self.msg("__setitem__ len: %d" % len(List.keys(self)))
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
		self.msg("__setitem__ after len: %d" % len(List.keys(self)))

	def getNetwork(self, BoxID):
		for net in List.keys(self):
			if self.__getitem__(net) == BoxID:
				return net
		return None

class PermissionList(List):
	'''
        The permission list contained a map to access a flow and its permission. A flow is ID by its header
    '''
	def __init__(self):
		List.__init__(self)

	def add(self, flowHeader, permission):
		if not isinstance(flowHeader, FlowHeader) or not isinstance(permission, Permission):
			self.err("add %s %s" % flowHeader, permission)
			return
		List.add(self, flowHeader, permission)

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
			self.ipFlows[sip][flowheader].add(flow)
	
	def __str__(self):
		msg ='['
		msg += str(self.timestamp)+" "
		msg += str(self.ipSet)+" "
		for ip in self.ipFlows:
			msg += str(self.ipFlows[ip])+" "
		msg+=']'
		return msg 

	def add(self, ip, flow:"Flow"):
		# if not isinstance(flow, Flow):
		# 	self.err("add flow is not a Flow instance")
		# 	return
		if not ipSet[ip]:
			self.ipSet[ip] = set()
		# if self.ipSet[ip]: