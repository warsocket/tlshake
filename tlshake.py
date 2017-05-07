#!/usr/bin/env python

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

import socket
import names
import argparse
from tls_protocol import make_client_hello, parse_server_response


def displayname(value, lookuptable={}):
	if value in lookuptable:
		return lookuptable[value]
	else:
		return "0x%s" % value.encode("hex")

def send_client_hello(sock, record_version, handshake_version, **options):
	
	
	# print ">>> %s:%d Tls Record version %s ClientHello version %s >> %s:%d" % ( sock.getsockname() + (displayname(record_version, names.tls_versions),) + (displayname(handshake_version, names.tls_versions),) + sock.getpeername() )
	print "TLS Record %s ClientHello %s >>> [%s:%d]" % ( (displayname(record_version, names.tls_versions), displayname(handshake_version, names.tls_versions)) + sock.getpeername())
	# print sock.getpeername()
	# print sock.getsockname()
	# print ""
	# print "================================ TLS PAYLOAD ================================"
	# print "TLS handshake record version: %s" % displayname(record_version, names.tls_versions)
	# print "Client Hello version: %s" % displayname(handshake_version, names.tls_versions)
	# print "Random: %s" % displayname()

	# if options["ciphers"]:
	# 	print "---------------------------------- CIPHERS ----------------------------------"		
	# 	for c in options["ciphers"]:
	# 		print displayname(c,names.tls_ciphers)

	return sock.sendall( make_client_hello(record_version, handshake_version, **options) ) 


def handle_server_response(sock):
	data = sock.recv( 0xFFFF )
	response = parse_server_response(data)

	if response["knownreply"]:
		extra = ""

		if response["contenttype"] == 22: #Server Hello
			extra = " %s %s %s" % ( displayname(response["hello_version"], names.tls_versions), displayname(response["hello_cipher"], names.tls_ciphers), displayname(response["hello_compression"], names.tls_compressions) )
		print "[%s:%d] <<< TLS Record %s %s%s" % (sock.getsockname() + (displayname(response["version"], names.tls_versions), displayname(response["contenttype"], names.tls_serverhello_contenttype), extra ))

	else:
		print "[%s:%d] <<< UNKNOWN RESPONSE" % sock.getsockname()
	return response


# Main 


parser = argparse.ArgumentParser(description='Send crafted TLS ClientHello to servers.')
parser.add_argument('host', type=str, help="IP address or hostname")
parser.add_argument('--port', '-p', type=int, default=443, help="Port to connect to (default: 443)")
args = parser.parse_args()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)
sock.connect((args.host, args.port))

send_client_hello(sock, "\x03\x03", "\x03\x03", ciphers=[names.tls_ciphers.keys()])
# send_client_hello(sock, "\x03\x03", "\x03\x03")
handle_server_response(sock)