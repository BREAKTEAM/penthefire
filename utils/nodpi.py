#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from scapy.all import *
from netfilterqueue import NetfilterQueue as nfqueue
import sys
import struct
import time
import socket

sys.path.append('python')
sys.path.append('build/python')


class generic_nodpi:
    def __init__(self, iface, queue=0, verbose=False):
        self.iface = iface
        self.verbose = verbose
        self.conn_dict = {}
        self.queue = queue
        self.ttl = 60

    def attack_ttl(self, ttl):
        if ttl > 64:
            delta = 128 - ttl - 1
        else:
            delta = 64 - ttl - 1
        return delta

    def forged_payload(self):
        return ""

    def cb(self, payload):
        data = payload.get_data()
        if "tun" not in self.iface:
            pkt = Ether() / IP(data)
        else:
            pkt = IP(data)
        if pkt[IP].proto != 6:
            return 1
        if pkt[TCP].flags == 18:
            self.ttl = pkt[IP].ttl
        if pkt[TCP].flags == 2:
            try:
                del self.conn_dict[pkt[TCP].sport]
            except:
                pass

        if pkt[TCP].flags & 8 != 0 and not self.conn_dict.has_key(pkt[TCP].sport):
            self.conn_dict[pkt[TCP].sport] = 1
            pkt[IP.ttl] = self.attack_ttl(self.ttl)
            pkt[TCP].payload = self.forged_payload()
            del pkt[IP].chksum
            del pkt[TCP].chksum
            del pkt[IP].len
            if self.verbose:
                sendp(pkt, iface=self.iface)
            else:
                sendp(pkt, iface=self.iface, verbose=0)
        if self.verbose:
            print "Packet accepted\n"
        payload.set_verdict(nfqueue.NF_ACCEPT)
        return 1

    def run(self):
        q = nfqueue.queue()
        if self.verbose:
            print "NFQ: open"
        q.open()

        if self.verbose:
            print "NFQ: bind"
        q.bind(socket.AF_INET)

        if self.verbose:
            print "NFQ: bind"
        q.bind(AF_INET)

        if self.verbose:
            print "NFQ: setting callback"
        q.set_callback(self.cb)

        if self.verbose:
            print "NFQ: creating queue"
        q.create_queue(self.queue)

        q.set_queue_maxlen(50000)

        if self.verbose:
            print "NFQ: trying to run"
        try:
            q.try_run()
        except KeyboardInterrupt, e:
            print "NFQ: interrupted"
        if self.verbose:
            print "NFQ: unbind"
        q.unbind(AF_INET)

        if self.verbose:
            print "NFQ: close"
        q.close()


class http_nodpi(generic_nodpi):
    def forged_payload(self):
        return """
GET /favicon.ico HTT/1.1
Host: www.example.org
"""
