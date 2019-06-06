#!/usr/bin/env python
# -*- coding: utf-8 -*-

#############################################
###   Using cryptography version - 2.4.2  ###
#############################################

##### Example sending command to server #####
#def send_commands(): 
#    stdin, stdout, stderr = ssh.exec_command('ls')
#    for line in stdout:
#        print('... ' + line.strip('\n'))
#    ssh.close()
#############################################

import paramiko
import socket
import sys

def auth(login, password, ip, port=22):  # SSH Connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, port, login, password)
    return ssh


def sftp(login, password, ip, port=22):  # SFTP Connection
    transport = paramiko.Transport(ip, port)
    transport.connect(username=login, password=password)
    this = paramiko.SFTPClient.from_transport(transport)
    return this

