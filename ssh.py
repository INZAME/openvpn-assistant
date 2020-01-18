#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#############################################
#     Using cryptography version - 2.4.2    #
#############################################

import paramiko
from base64 import b64encode, b64decode
import configparser
import time
import os
import socket
import struct
import re
from shutil import rmtree

class OpenVPN:

    def __init__(self, login, password, ip, port=22):
        '''
        ssh_client, sftp_client
        '''
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh_client.connect(ip, port, login, password)
        self.sftp_transport = paramiko.Transport(ip, port)
        self.sftp_transport.connect(username=login, password=password)
        self.sftp_client = paramiko.SFTPClient.from_transport(self.sftp_transport)

    def add_users(self, state='reg') -> list:
        '''
        Read users from server and return list
        reg state: return registered users
        rev state: return revoked users
        '''
        command = 'cat /etc/openvpn/easy-rsa/keys/index.txt'
        stdin, stdout, stderr = self.ssh_client.exec_command(command)
        if str(state) == 'reg':
            usr_reg = []
            for line in stdout:
                new_line = line.split('/')
                if line[0] == 'V':
                    usr_reg.append(new_line[6].replace('CN=', ''))
            return usr_reg
        elif str(state) == 'rev':
            usr_rev = []
            for line in stdout:
                new_line = line.split('/')
                if line[0] == 'R':
                    usr_rev.append(new_line[6].replace('CN=', ''))
            return usr_rev

    def show_conf(self) -> list:
        '''
        Parse OpenVPN config to list
        '''
        config = []
        stdin, stdout, stderr = self.ssh_client.exec_command('cat /etc/openvpn/server.conf')
        for line in stdout:
            if line != '\n':
                config.append(line)
        return config