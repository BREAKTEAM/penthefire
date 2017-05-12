#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import struct
import re
import os


class generic_server:
    def __init__(self, ip, port, verbose=False):
        self.port = port
        self.family = socket.AF_INET
        self.verbose = verbose
        self.conn = None
        self.conn1 = None
        self.message = None
        self.ip = ip

    def listen(self):
        if self.port < 1024 and not os.geteuid() == 0:
            raise Exception('Need to be root')
        self.conn = socket.socket(self.family, socket.SOCK_STREAM)
        self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.conn.bind((self.ip, self.port))
        self.conn.listen(1)
        self.conn, addr = self.conn.accept()
        self.negotiate()
        res = self.decode_command()
        self.conn1.sendall("%s:%d" % res)
        self.conn1.close()
        self.conn.close()

    def negotiate(self):
        self.message = self.conn1.recv(1024)

    def decode_command(self):
        return self.message

    def run(self):
        try:
            self.listen()
        except socket.error:
            print socket.error.string
        except Exception, err:
            print err

        if self.verbose:
            print "Received: %s" % (self.message)
        return self.decode_command()

    def numtodotquad(self, ip):
        return socket.inet_ntoa(struct.pack('!L', ip))


class irc(generic_server):
    def decode_command(self):
        r = re.search("CHAT (\d+) (\d+)", self.message)
        return (self.numtodotquad(int(r.group(1))), int(r.group(2)))


class ftp(generic_server):
    def decode_command(self):
        r = re.search('PORT ([\d,]+)\r\n', self.message)
        rsplit = r.group(1).split(',')
        return ('.'.join(rsplit[0:4]), int(rsplit[4]) * 256 + int(rsplit[5]))

    def negotiate(self):
        self.ccon1.recv(1024)
        self.conn1.sendall('200 wolffirewall\r\n')
        self.message = self.conn1.recv(2014)


class ftp6(ftp):
    def __init__(self, ip, port, verbose=False):
        generic_server.__init__(self, ip, port, verbose)
        self.family = socket.AF_INET6

    def decode_command(self):
        r = re.search("EPRT \|2\|(.+)\|(\d+)\|\r\n", self.message)
        return (r.group(1), int(r.group(2)))
