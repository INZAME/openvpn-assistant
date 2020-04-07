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
        """
        ssh_client, sftp_client
        """
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh_client.connect(ip, port, login, password)
        self.sftp_transport = paramiko.Transport(ip, port)
        self.sftp_transport.connect(username=login, password=password)
        self.sftp_client = paramiko.SFTPClient.from_transport(self.sftp_transport)

    def add_users(self, state='reg') -> list:
        """
        Read users from server and return list
        reg state: return registered users
        rev state: return revoked users
        """
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
        """
        Parse OpenVPN config to list
        """
        config = []
        stdin, stdout, stderr = self.ssh_client.exec_command('cat /etc/openvpn/server.conf')
        for line in stdout:
            if line != '\n':
                config.append(line)
        return config

    def ovpn_version(self) -> str:
        """
        Return OpenVPN version
        """
        version = ''
        stdin, stdout, stderr = self.ssh_client.exec_command('openvpn --version')
        for line in stdout:
            version = line.split()[1]
            break
        return version

    def download_profiles(self, user_list, subfolder=True):
        """
        Download profiles from user list
        """
        usr_reg = []
        con_ip = str(self.ssh_client.get_transport().sock.getpeername()[0])
        self.sftp_client.get('/etc/openvpn/server.conf', './tmp.conf')
        server_conf = open('./tmp.conf', 'r')
        keys_folder = '/etc/openvpn/easy-rsa/keys/'
        index = 'cat /etc/openvpn/easy-rsa/keys/index.txt'
        for line in server_conf:
            if re.match(r'port', line):
                port = line.split()[1]
            elif re.match(r'proto', line):
                proto = line.split()[1]
        stdin, stdout, stderr = self.ssh_client.exec_command(index)
        for line in stdout:
            new_line = line.split('/')
            if line[0] == 'V':
                usr_reg.append(new_line[6].replace('CN=', ''))
        for new_user in user_list:
            settings = ['####################################',
                        '#   Created by OpenVPN Assistant   #',
                        '####################################',
                        '',
                        'nobind', 'client',
                        '',
                        '# Remote server here',
                        f'remote {con_ip} {port}',
                        '',
                        '# Path to certificates here',
                        'ca ca.crt', f'cert {new_user}.crt', f'key {new_user}.key',
                        '',
                        '# Windows route method',
                        'route-method exe', '', 'remote-cert-tls server',
                        'dev tun', f'proto {proto}',
                        'resolv-retry infinite', 'persist-key', 'persist-tun']
            if settings[20] == 'proto udp':
                settings.append('explicit-exit-notify')
            if new_user not in usr_reg:
                end = f'; source ./vars; ./build-key --batch {new_user}'
                self.ssh_client.exec_command('cd ' + keys_folder[:-5] + end)
                time.sleep(1)
            path = f'./profiles/{new_user}' if subfolder else f'./{new_user}'
            if os.path.exists(path):
                rmtree(path)
            os.makedirs(path)
            files = ('ca.crt', str(new_user + '.crt'), str(new_user + '.key'))
            for name in files:
                self.sftp_client.get(str(keys_folder + name), str(f'{path}/{name}'))
                profile = open(f'{path}/{new_user}.ovpn', 'w')
                for line in settings:
                    profile.write(line + '\n')
                profile.close()
        server_conf.close()
        os.remove('./tmp.conf')

    def get_tun0(self):
        """
        Get tunnel IP
        """
        ip = []
        ifaces = ('tun0', 'tun1', 'tun2')
        end = " | grep 'inet' | cut -d: -f2 | awk '{print $2}'"
        for iface in ifaces:
            stdin, stdout, stderr = self.ssh_client.exec_command(
                str("ifconfig " + iface + end))
            for line in stdout:
                edited = line.strip()
                if edited != '':
                    ip.append(edited)
                    ip.append(iface)
        return ip

    def get_ip(self):
        """
        Get remote VM's local IP
        """
        ip = []
        ifaces = ('eth0', 'eth1', 'ens3', 'en3s0',
                'ens33', 'en0s3', 'enp0s3', 'enp3s0')
        end = " | grep 'inet' | cut -d: -f2 | awk '{print $2}'"
        for iface in ifaces:
            stdin, stdout, stderr = self.ssh_client.exec_command(str("ifconfig " + iface + end))
            for line in stdout:
                edited = line.strip()
                if edited != '':
                    ip.append(edited)
                    ip.append(iface)
        return ip
    
    def close(self):
        """
        Close connections
        """
        self.sftp_client.close()
        self.ssh_client.close()