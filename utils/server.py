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
