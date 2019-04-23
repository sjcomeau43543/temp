import numpy as np

# burst structure
class Burst():
	timestamp_lastrecvppacket = 0.0
	flows = []
	ppackets = []

	def __init__(self, firstppacket):
		self.add_ppacket(firstppacket)
		self.timestamp_lastrecvppacket = firstppacket.timestamp
		self.flows = []	
		self.ppackets = []
	
	def add_ppacket(self, ppacket):
		self.timestamp_lastrecvppacket = ppacket.timestamp
		for flow in self.flows:
			if flow.src_ip == ppacket.src_ip and flow.dst_ip == ppacket.dst_ip and flow.src_port == ppacket.src_port and flow.dst_port == ppacket.dst_port and flow.protocol == ppacket.protocol:
				flow.add_ppacket(ppacket)
				return
		newFlow = Flow(ppacket)
		self.flows.append(newFlow)
		self.ppackets.append(ppacket)


	def clean_me(self):
		self.timestamp_lastrecvppacket = 0.0
		for flow in self.flows:
			flow.clean_me()
			self.flows.remove(flow)
		self.flows = []	

	def pretty_print(self):
		print("~~~ New Burst ~~~")
		for flow in self.flows:
			flow.one_line_print()
			
	def write_to_csv(self, writer):
		for flow in self.flows:
			flow.write_to_csv(writer)
			
	def get_data(self):
		if len(self.flows) == 0:
			return None, None
		features = self.flows[0].add_first_feature_row()
		labels = self.flows[0].add_first_label_row()
		for flow in self.flows[1:]:
			features = flow.add_feature_row(features)
			labels = flow.add_label_row(labels)

		# print 'length', len(self.flows)
		if len(self.flows) == 1:
			# print 'returning bad one'
			return features.reshape(1,-1), labels.reshape(1,-1)

#		print features,labels
		return features, labels
			
			

class Flow():
	timestamp = None
	src_ip = None
	dst_ip = None
	src_port = None
	dst_port = None
	protocol = None
	num_packets_sent = 0
	num_bytes_sent = 0
	packets = []
	length = 0
	integer_protocol = 0
	label = None
	ethtype = None 
	ttl = None
	flags = None 
	proto = None

	# new ones
	mean_len = 0
	total_duration = None 
	

	def __init__(self, ppacket):
		self.timestamp = ppacket.timestamp
		self.src_ip = ppacket.src_ip
		self.dst_ip = ppacket.dst_ip
		self.src_port = ppacket.src_port
		self.dst_port = ppacket.dst_port
		self.protocol = ppacket.protocol
		self.packets = []
		self.add_ppacket(ppacket)
		if self.protocol == 'UDP':
			self.integer_protocol = 1
		elif self.protocol == 'TCP':
			self.integer_protocol = 2
		self.label = ppacket.label
		self.ethtype = ppacket.ethtype 
		self.ttl = ppacket.ttl 
		self.flags = ppacket.flags 
		self.proto = ppacket.proto
		self.num_bytes_sent = ppacket.num_bytes
		self.mean_len = ppacket.num_bytes
		self.total_duration = ppacket.timestamp - self.timestamp


	def add_ppacket(self, ppacket):
		self.packets.append(ppacket)
		self.num_packets_sent += 1
		self.num_bytes_sent += ppacket.num_bytes
#		self.ttl = (self.ttl + ppacket.ttl) / 2
		self.mean_len = (self.mean_len + ppacket.num_bytes) / 2
		self.total_duration = ppacket.timestamp - self.timestamp

	def clean_me(self):
#		print self.packets
		for packet in self.packets:
			self.packets.remove(packet)		

		self.packets = []
#		print self.packets	
		
	def pretty_print(self):
		print("~~~ New Flow ~~~")
		print("Source IP: {}".format(self.src_ip))
		print("Source Port: {}".format(self.src_port))
		print("Destination IP: {}".format(self.dst_ip))
		print("Destination Port: {}".format(self.dst_port))
		print("Protocol: {}".format(self.protocol))
		print("Timestamp: {}".format(self.timestamp))
		print("Packets sent: {}".format(self.num_packets_sent))
		print("Bytes sent: {}".format(self.num_bytes_sent))

	def one_line_print(self):
#		print self.packets
		print("{} {} {} {} {} {} {} {} {}".format(self.timestamp, self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol, self.num_packets_sent, self.num_bytes_sent, self.label))
#		for packet in self.packets:
#			packet.one_line_print()
		
	def write_to_csv(self, writer):
		# write the flow to the csv
		writer.writerow([self.timestamp, self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol, self.num_packets_sent, self.num_bytes_sent, self.label, self.integer_protocol, self.ethtype, self.ttl, self.flags, self.proto, self.mean_len, self.total_duration])
		
		
	def add_first_feature_row(self):
		return np.array([self.num_packets_sent, self.integer_protocol, self.num_bytes_sent, self.mean_len, self.total_duration])
		
	def add_first_label_row(self):
		return np.array([self.label])
		
	def add_feature_row(self, features):
		return np.vstack((features, [self.num_packets_sent, self.integer_protocol, self.num_bytes_sent, self.mean_len, self.total_duration]))
		
	def add_label_row(self, labels):
		return np.vstack((labels, [self.label]))
		
	def update_label(self, label):
		self.label = label
		
		for packet in self.packets:
			packet.label = label	 
		
# packet structure
class Packet():
	src_ip = None
	dst_ip = None
	src_port = None
	dst_port = None
	protocol = None
	timestamp = None
	num_bytes = None
	label = None
	ethtype = None 
	ttl = None
	flags = None 
	proto = None
	
	def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol, timestamp, num_bytes, appname, ethtype, ttl, flags, proto):
		#TODO: Make __init__ populate number of bytes
		self.src_ip = src_ip
		self.src_port = src_port
		self.dst_ip = dst_ip
		self.dst_port = dst_port
		self.protocol = protocol
		self.timestamp = float(timestamp)
		self.num_bytes = num_bytes
		self.label = appname
		self.ethtype = ethtype 
		self.ttl = ttl
		self.flags = flags 
		self.proto = proto

	def pretty_print(self):
		print("~~~ New Packet ~~~")
		print("Source IP: ", self.src_ip)
		print("Source Port: ", self.src_port)
		print("Destination IP: ", self.dst_ip)
		print("Destination Port: ", self.dst_port)
		print("Protocol: ", self.protocol)
		print("Timestamp: ", self.timestamp)
		print("Label: ", self.label)

	def one_line_print(self):
		print("\t{} {} {} {} {} {} {}".format(self.timestamp, self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol, self.label))