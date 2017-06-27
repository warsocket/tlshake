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
from tlshake import displayname, send_client_hello, handle_server_response, socket_from_args

def tlsenum(args):

	for version in names.tls_versions.keys():

		# version = names.rev_tls_versions['TLSv1.2']
		print ""
		print "=========== %s ==========" % names.tls_versions[version]

		ciphers = set(names.tls_ciphers.keys())

		data = {"hello_cipher": ""} #stub to handle start condition
		emit = False
		while "hello_cipher" in data:

			if emit:
				print displayname(data["hello_cipher"], names.tls_ciphers)
				ciphers.remove(data["hello_cipher"])
			emit = True

			sock = socket_from_args(args)
			send_client_hello(sock, version, version, ciphers, args.p_compressions)
			data = handle_server_response(sock)
			
scripts = {
	'tlsenum': tlsenum,
}