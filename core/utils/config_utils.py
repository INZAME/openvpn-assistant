#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import paramiko
from base64 import b64encode, b64decode
import configparser
import os
import io


# --- Reading .ini config ---
def read_config(window, cname):
    config = configparser.ConfigParser()
    if not os.path.exists(cname):
        config['DEFAULT'] = {'Login': 'root',
                             'Password': 'empty',
                             'IP': '127.0.0.1',
                             'Port': '22'}
        with open(cname, 'w') as configfile:
            config.write(configfile)
    config.read(cname)
    try:
        config['USER']['Login']
    except Exception:
        window.login.setText(config['DEFAULT']['Login'])
        window.ip.setText(config['DEFAULT']['IP'])
        window.port.setText(config['DEFAULT']['Port'])
        window.password.setText(config['DEFAULT']['Password'])
    else:
        window.login.setText(config['USER']['Login'])
        window.ip.setText(config['USER']['IP'])
        window.port.setText(config['USER']['Port'])
        pswd = b64decode(config['USER']['Password'])
        window.password.setText(pswd.decode('utf-8'))


# --- Update config with user params ---
def write_config(name, **args):
    config = configparser.ConfigParser()
    crypted = b64encode(bytes(args['password'], 'utf-8')).decode('utf-8')
    config['DEFAULT'] = {'Login': 'root',
                         'Password': 'empty',
                         'IP': '127.0.0.1',
                         'Port': '22'}
    config['USER'] = {'Login': args['login'],
                      'Password': crypted,
                      'IP': args['ip'],
                      'Port': args['port']}
    with open(name, 'w') as configfile:
        config.write(configfile)
    print('[DEBUG] Successfully write config!')


def server_config(**kwargs):
    config = [f"local {kwargs['local']}", f"port {kwargs['port']}", f"proto {kwargs['proto']}",
              f"server {kwargs['server_ip']} {kwargs['server_port']}", 'ifconfig-pool-persist ipp.txt',
              'push "redirect-gateway def1"']
    config.extend(('dev tun', 'ca ca.crt',
                   'cert server.crt', 'key server.key',
                   ';crl-verify /etc/openvpn/easy-rsa/keys/crl.pem',
                   'dh dh2048.pem'))
    if kwargs['dns'] == 'OpenNIC':
        config.append('dhcp-option DNS 91.217.137.37')
        config.append('dhcp-option DNS 172.104.136.243')
    elif kwargs['dns'] == 'Google':
        config.append('dhcp-option DNS 8.8.8.8')
        config.append('dhcp-option DNS 8.8.4.4')
    elif kwargs['dns'] == 'Yandex':
        config.append('dhcp-option DNS 77.88.8.8')
        config.append('dhcp-option DNS 77.88.8.1')
    config.extend(('keepalive 10 120', 'tls-server',
                   'auth SHA512', 'cipher AES-256-CBC',
                   'user nobody', 'group nogroup',
                   'persist-key', 'persist-tun'))
    if kwargs['c2c']:
        config.append('client-to-client')
    if kwargs['logging']:
        config.extend(('status /dev/null', 'log /dev/null'))
    else:
        config.extend(('status openvpn-status.log',
                       'log openvpn.log', 'verb 3'))
    conf = io.open('./server.conf', 'w', newline='\n')
    for line in config:
        conf.write(line + '\n')
    conf.close()
    return config
