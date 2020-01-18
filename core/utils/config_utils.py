#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import paramiko
from base64 import b64encode, b64decode
import configparser
import os


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
