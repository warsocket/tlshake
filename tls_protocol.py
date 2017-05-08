#Tlshake
#Copyright (C) 2016  Bram Staps
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU Affero General Public License as
#published by the Free Software Foundation, either version 3 of the
#License, or (at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU Affero General Public License for more details.
#
#You should have received a copy of the GNU Affero General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.

import struct

#convenience functions

def to_short(num):
	return struct.pack("!H", num)

def from_short(num):
	return struct.unpack("!H", num)[0]

def to_byte(num):
	return chr(num)

def from_byte(num):
	return ord(num)


def pkt(*argv):
	if len(argv) > 1:
		return "".join(map (pkt, argv))
	else:
		if hasattr(argv[0], "__iter__"):
			return "".join(map(pkt, argv[0]))
		else:
			return argv[0]

def sizeme_short(pre_data, post_data): #return data with size of the data represented at %s ergo : sizeme("te%sst") -> t e 0x00 0x04 s t
	return "".join([pre_data, to_short(len(pre_data) + len(post_data)), post_data])

def sizeme_byte(pre_data, post_data): #return data with size of the data represented at %s ergo : sizeme("te%sst") -> t e 0x00 0x04 s t
	return "".join([pre_data, to_byte(len(pre_data) + len(post_data)), post_data])

def presize_short(*data):
	data = pkt(data)
	return sizeme_short("", data)

def presize_byte(*data):
	data = pkt(data)
	return sizeme_byte("", data)


class Parser():
	def __init__(self, data):
		self.data = data
		self.offset = 0

	def get(self, i):
		oldoffset = self.offset
		self.offset += i
		return self.data[oldoffset : self.offset]

	def seek(self, i):
		self.offset = i

	def getshortnum(self):
		return from_short(self.get(2))

	def getbytenum(self):
		return from_byte(self.get(1))

	def get_struct_short(self):
		return self.get(self.getshortnum())

	def get_struct_byte(self):
		return self.get(self.getbytenum())


################################################################################
# non TLS-specific helper functions above                                      #
################################################################################

def make_client_hello(record_version, handshake_version, **options):
	#defaults
	cipherlist=[]
	extensionlist=[]
	compressionmethods=["\x00"]
	random = "\xFF"*32
	sessionid = "\x00"*32

	if "ciphers" in options: cipherlist = options["ciphers"]
	if "extensions" in options: extensionlist = options["extensions"]
	if "compressions" in options: compressionmethods = options["compressions"]
	if "random" in options: random = options["random"]
	if "sessionid" in options: sessionid = options["sessionid"]

	return pkt(
		"\x16", 
		record_version, 
		presize_short( 
			"\x01", 
			"\x00", 
			presize_short( 
				handshake_version, 
				random, 
				# chr(len(sessionid)), sessionid, 
				presize_byte(sessionid),
				presize_short(cipherlist), 
				# chr(len(compressionmethods)), "".join(map(chr,compressionmethods)),
				presize_byte(compressionmethods),
				presize_short(extensionlist) 
				) 
			) 
		)

def parse_server_response(data):
	p = Parser(data)
	s = {"knownreply": False}
	try:
		s["contenttype"] = p.getbytenum()
		s["version"] = p.get(2)
		s["length"] = p.getshortnum()

		if s["contenttype"] == 22: #ok
			s["hello_type"] = p.getbytenum()
			p.get(1) #discard junk byte
			s["hello_length"] = p.getshortnum()
			s["hello_version"] = p.get(2)
			s["hello_random"] = p.get(32)
			s["hello_sessionid"] = p.get_struct_byte()
			s["hello_cipher"] = p.get(2)
			s["hello_compression"] = p.get(1)
		elif s["contenttype"] == 21: #Alert
			s["alert_level"] = p.getbytenum()
			s["alert_description"] = p.getbytenum()
		else:
			raise() #break
		s["knownreply"] = True
	except:
		pass

	return s