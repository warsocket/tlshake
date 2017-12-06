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


def smtp(sock):
	sock.recv(0xFFFF)
	sock.sendall("STARTTLS\r\n")
	sock.recv(0xFFFF)


available = {
	"smtp": smtp
}