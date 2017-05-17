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
			send_client_hello(sock, version, version, ciphers=ciphers)
			data = handle_server_response(sock)

scripts = {
	'tlsenum': tlsenum,
}