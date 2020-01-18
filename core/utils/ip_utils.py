#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import os

def cidr_to_netmask(cidr):
    '''
    Convert ip/mask to tuple
    '''
    network, net_bits = cidr.split('/')
    host_bits = 32 - int(net_bits)
    netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
    return network, netmask

def rm_temp():
    os.remove('./server.conf')
    os.remove('./vars')