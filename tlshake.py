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
import starttls
import argparse
from tls_protocol import make_client_hello, parse_server_response


def socket_from_args(args):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(2)
	sock.connect((args.host, args.port))
	if args.starttls:
		starttls.available[args.starttls](sock)
	return sock


def displayname(value, lookuptable={}):
	if value in lookuptable:
		return lookuptable[value]
	else:
		return "0x%s" % value.encode("hex")

#This should in time support all params that were being processed in the beginning
def send_client_hello(sock, record_version, handshake_version, verbosity=0, **options):

	if verbosity > 1:
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


def handle_server_response(sock, verbosity=0):
	try:
		data = sock.recv( 0xFFFF )
	except Exception as e:
		print e
		return {}

	response = parse_server_response(data)

	if response["knownreply"]:
		extra = ""

		if response["contenttype"] == 22: #Server Hello
			extra = " %s %s %s" % ( displayname(response["hello_version"], names.tls_versions), displayname(response["hello_cipher"], names.tls_ciphers), displayname(response["hello_compression"], names.tls_compressions) )
		if verbosity > 1:
			print "[%s:%d] <<< TLS Record %s %s%s" % (sock.getsockname() + (displayname(response["version"], names.tls_versions), displayname(response["contenttype"], names.tls_serverhello_contenttype), extra ))
		elif verbosity == 1:
			print displayname(response["hello_cipher"], names.tls_ciphers)

	else:
		if verbosity > 1:
			print "[%s:%d] <<< UNKNOWN RESPONSE" % sock.getsockname()
	return response



def get_param_value(string, lookuptable = {}):
	if string in lookuptable:
		return lookuptable[string]
	else:
		try:
			assert(string[0:2] == "0x")
			return string[2:].decode("hex")
		except:
			print "Cannot parse '%s' as payload, please supply a raw value in hex  (0x....)" % string
			print "You can also use one (or multiple, depending on the option) of the following known values: %s" % " ".join(lookuptable.keys())
			exit(1)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Send crafted TLS ClientHello to servers.')
	parser.add_argument('--verbose', type=int, default=2, help="Verbosity level (0-3) (default:2)")
	parser.add_argument('host', type=str, help="IP address or hostname")
	parser.add_argument('--port', '-p', type=int, default=443, help="Port to connect to (default: 443)")
	parser.add_argument('--record-version', '-v', type=str, default="TLSv1.2", help="Client Hello TLS version (default: TLSv1.2)")
	parser.add_argument('--hello-version', type=str, help="Record layer version (default: [used record version])")
	parser.add_argument('--ciphers', '-c', type=str, nargs="*", help="Cipher(s) to request (default: All known ciphers)")
	parser.add_argument('--compressions', '-z', type=str, nargs="*", help="Compressions(s) to request (default: All known compressions)")

	#TODO TLS addons likle SNI, EDHC curves SCSV, etc
	parser.add_argument('--starttls', type=str, help="Use Starttls")
	parser.add_argument('--script', '-s', type=str, nargs="+", help="Script name and params.")
	args = parser.parse_args()

	if args.script:
		import script
		script.scripts[args.script[0]](args)# get fulladdr from args

	else:
		if not args.hello_version: args.hello_version = args.record_version
		record_version = get_param_value(args.record_version, names.rev_tls_versions)
		hello_version = get_param_value(args.record_version, names.rev_tls_versions)

		if args.ciphers: 
			ciphers = map(lambda x: get_param_value(x, names.rev_tls_ciphers), args.ciphers)
		else:
			ciphers = names.tls_ciphers.keys()

		if args.compressions: 
			compressions = map(lambda x: get_param_value(x, names.rev_tls_compressions), args.compressions)
		else:
			compressions = names.tls_compressions.keys()


		if args.verbose > 0:
			print ""

		sock = socket_from_args(args)
		send_client_hello(sock, record_version, hello_version, args.verbose, ciphers=ciphers, compressions=compressions)
		handle_server_response(sock, args.verbose)