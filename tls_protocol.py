# Tlshake
# Copyright (C) 2016  Bram Staps

# This file is part of Tlshake.
# Tlshake is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# Tlshake is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with Tlshake. If not, see <http://www.gnu.org/licenses/>.


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
	return [pre_data, to_short(len(pre_data) + len(post_data)), post_data]

def sizeme_byte(pre_data, post_data): #return data with size of the data represented at %s ergo : sizeme("te%sst") -> t e 0x00 0x04 s t
	return [pre_data, to_byte(len(pre_data) + len(post_data)), post_data]

def presize_short(*data):
	data = pkt(data)
	return sizeme_short("", data)

def presize_byte(*data):
	data = pkt(data)
	return sizeme_byte("", data)

def iff(statement, *data):
	if statement:
		return data
	else:
		return ""

#retuirn function instead of reolved statement at cnlude time which prevents unreolved symbol erros
def ifff(statement, func2data):
	if statement:
		return func2data()
	else:
		return ""

def resolve(d, k):
	try:
		return d[k]
	except:
		return ""


class Parser():
	def __init__(self, data):
		self.data = data
		self.offset = 0

	def get(self, i=None):
		if i != None:
			oldoffset = self.offset
			self.offset += i
			return self.data[oldoffset : self.offset]
		else: # get all
			oldoffset = self.offset
			self.offset = len(self.data)
			return self.data[oldoffset:]

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

def make_client_hello(record_version, handshake_version, cipherlist, compressionmethods, **options):
	#defaults
	# cipherlist=[]
	extensionlist=[]
	# compressionmethods=["\x00"]
	random = "\xFF"*32
	sessionid = "\x00"*32

	# if "ciphers" in options: cipherlist = options["ciphers"]
	# if "extensions" in options: extensionlist = options["extensions"]
	# if "compressions" in options: compressionmethods = options["compressions"]
	if "random" in options: random = options["random"]
	if "sessionid" in options: sessionid = options["sessionid"]

	#plugins
	addons = []

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
				presize_short(
					ifff(options["sni"] != None,
						lambda: pkt(
							"\x00\x00",
							presize_short(
								presize_short(
									"\x00",
									presize_short(
										options['sni']
									)
								)
							)
						)
					),
					ifff("supportedversions" in options, 
						lambda: pkt(
							"\x00\x2B", #(43) TLs1.3 draft vsupported versions addons
							presize_short(
								presize_byte(
									options['supportedversions']
								)
							)
						)
					),					
					ifff("ecpf" in options, 
						lambda: pkt(
							"\x00\x0B", #ellicptic curve point format magic number
							presize_short(
								presize_byte(
									options['ecpf']
								)
							)
						)
					),
					ifff("ec" in options, 
						lambda: pkt(
							"\x00\x0A", #ellicptic curve magic number
							presize_short(
								presize_short(
									options['ec']
								)
							)
						)
					),
					iff(options["ticket"],
						pkt(
						"\x00\x23",
						presize_short(""),
						)
					),
					iff(options["tls13goop"],
						pkt([
						"\x00\x16\x00\x00", 
						"\x00\x17\x00\x00", 
						"\x00\x0d\x00\x30\x00\x2e\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x03\x03\x02\x03\x03\x01\x02\x01\x03\x02\x02\x02\x04\x02\x05\x02\x06\x02", 
						"\x00\x2d\x00\x02\x01\x01", 
						"\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20\x64\xff\x26\xae\xb2\xa6\x45\x18\xaa\x1a\xa1\x8d\xab\x2e\x10\x7a\x57\xa9\x89\x95\x0b\x0a\x61\x6b\x18\x9a\x7a\x77\xd5\x47\xa9\x4a"
						])# hack addon blobs
					)
				)
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
			s["raw_addons"] = p.get(p.getshortnum())
			s["rest"] = p.get() # get the rest
		elif s["contenttype"] == 21: #Alert
			s["alert_level"] = p.getbytenum()
			s["alert_description"] = p.getbytenum()
		else:
			raise() #break
		s["knownreply"] = True
	except:
		pass

	return s
