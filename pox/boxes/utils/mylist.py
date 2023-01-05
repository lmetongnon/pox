import logging
from pox.boxes.utils.tools import Permission
from pox.boxes.utils.flow import FlowHeader
lg = logging.getLogger('list')

from pox.lib.addresses import IPAddr, IPAddr6

class List(object):
	def __init__(self):
		self.records = {}

	def add(self, key, value):
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
	def __init__(self):
		List.__init__(self)

	def add(self, networks, boxID):
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
	
	def values(self):
		return [self[key] for key, _ in self.keys()]

	def _check(self, network, boxIP):
		self.msg("_check : %s %s" % (network, boxIP))
		if isinstance(boxIP, IPAddr) and not isinstance(network, IPAddr):
			self.msg("network address %s is not ipv4" % network)
			return
		elif isinstance(boxIP, IPAddr6) and not isinstance(network, IPAddr6):
			self.msg("network address %s is not ipv6" % network)
			return

	def exists(self, network):
		if List.exists(network):
			return True
		for net in List.keys():
			if net.in_network(network):
				return True
		return False

	def __getitem__(self, network):
		self.msg("__getitem__ len: %d" % len(List.keys(self)))
		if List.exists(self, network):
			return List__getitem__(self, network)
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

class PermissionList(List):
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
