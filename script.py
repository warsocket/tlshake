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
import re
from tlshake import displayname, send_client_hello, handle_server_response, socket_from_args, options_from_args

def enumciphers(args):

	for version in names.tls_versions.keys():

		# version = names.rev_tls_versions['TLSv1.2']
		if args.verbose > 1:
			print ""
			print "=========== %s ==========" % names.tls_versions[version]

		ciphers = set(names.tls_ciphers.keys())

		options = options_from_args(args)

		data = {"hello_cipher": ""} #stub to handle start condition
		emit = False
		while "hello_cipher" in data:

			if emit:
				print displayname(data["hello_cipher"], names.tls_ciphers)
				ciphers.remove(data["hello_cipher"])
			emit = True

			sock = socket_from_args(args)
			send_client_hello(sock, version, version, ciphers, args.p_compressions, **options)
			data = handle_server_response(sock)


def enumcurves(args):
	# create copnnection with an EC cipher
	rx = re.compile("^TLS_ECDHE?_")

	ciphers = filter( lambda key: rx.match(names.tls_ciphers[key]), names.tls_ciphers )

	options = options_from_args(args)
	options["ec"] = names.elliptic_curves.keys()
	options["ecpf"] = names.ec_points.keys()

	sock = socket_from_args(args)
	send_client_hello(sock, names.rev_tls_versions["SSLv3.0"], names.rev_tls_versions["TLSv1.2"], ciphers, args.p_compressions, **options)
	data = handle_server_response(sock)


	if "hello_cipher" not in data:
		print "Elliptic Curve ciphers not supported."
		return

	version, hello_version = data["version"], data["hello_version"]

	cipher = data["hello_cipher"]

	if args.verbose > 1:
		print "going with cipher %s" % displayname(data["hello_cipher"], names.tls_ciphers)

	emit = False
	#We need a for loop because not all servers communicate back ciphers

	for curve in options["ec"]:
		o = dict(options)
		o["ec"] = [curve]

		sock = socket_from_args(args)
		send_client_hello(sock, version, hello_version, ciphers, args.p_compressions, **o)
		data = handle_server_response(sock)
		if "hello_cipher" in data:
			print displayname(curve, names.elliptic_curves)


			
scripts = {
	'enumciphers': enumciphers,
	'enumcurves': enumcurves,
}