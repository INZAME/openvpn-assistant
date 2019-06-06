import time
import os
import socket
import struct
import re
from shutil import rmtree


def add_users(ssh, state='reg'):  # Add users to var
    stdin, stdout, stderr = ssh.exec_command('cat /etc/openvpn/easy-rsa/keys/index.txt')
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


def show_conf(ssh):
    config = []
    stdin, stdout, stderr = ssh.exec_command('cat /etc/openvpn/server.conf')
    for line in stdout:
        if line != '\n':
            config.append(line)
    return config


def download_profiles(ssh, sftp, user_list, subfolder=True):  # Func for downloading users
    usr_reg = []
    con_ip = str(ssh.get_transport().sock.getpeername()[0])
    sftp.get('/etc/openvpn/server.conf', './tmp.conf')
    server_conf = open('./tmp.conf', 'r')
    for line in server_conf:
        if re.match(r'port', line):
            port = line.split()[1]
        elif re.match(r'proto', line):
            proto = line.split()[1]
    stdin, stdout, stderr = ssh.exec_command('cat /etc/openvpn/easy-rsa/keys/index.txt')
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
                    'route-method exe', '', 'remote-cert-tls server', 'dev tun', f'proto {proto}',
                    'resolv-retry infinite', 'persist-key', 'persist-tun', 'explicit-exit-notify']
        if new_user not in usr_reg:
            ssh.exec_command('cd /etc/openvpn/easy-rsa; source ./vars; ./build-key --batch {}'.format(new_user))
            time.sleep(1)
        if subfolder:
            if os.path.exists(f'./profiles/{new_user}'):
                rmtree(f'./profiles/{new_user}')
            os.makedirs(f'./profiles/{new_user}')
            files = ('ca.crt', str(new_user + '.crt'), str(new_user + '.key'))
            for name in files:
                sftp.get(str('/etc/openvpn/easy-rsa/keys/' + name), str(f'./profiles/{new_user}/{name}'))
                ovpn = open(f'./profiles/{new_user}/{new_user}.ovpn', 'w')
                for line in settings:
                    ovpn.write(line + '\n')
                ovpn.close()
        else:
            if os.path.exists(f'./{new_user}'):
                rmtree(new_user)
            os.mkdir(new_user)
            files = ('ca.crt', str(new_user + '.crt'), str(new_user + '.key'))
            for name in files:
                sftp.get(str('/etc/openvpn/easy-rsa/keys/' + name), str(f'./{new_user}/{name}'))
                ovpn = open(f'./{new_user}/{new_user}.ovpn', 'w')
                for line in settings:
                    ovpn.write(line + '\n')
                ovpn.close()
    server_conf.close()
    os.remove('./tmp.conf')

def cidr_to_netmask(cidr):
    network, net_bits = cidr.split('/')
    host_bits = 32 - int(net_bits)
    netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
    return network, netmask

def get_tun0(ssh):
    ifaces = ('tun0', 'tun1', 'tun2')
    ip = []
    for this in ifaces:
        stdin, stdout, stderr = ssh.exec_command(
            str("ifconfig " + this + " | grep 'inet' | cut -d: -f2 | awk '{print $2}'"))
        for line in stdout:
            edited = line.strip()
            if edited != '':
                ip.append(edited)
                ip.append(this)
    return ip

def get_ip(ssh):
    ifaces = ('eth0', 'eth1', 'ens3', 'en3s0', 'ens33', 'en0s3', 'enp0s3', 'enp3s0')
    ip = []
    for this in ifaces:
        stdin, stdout, stderr = ssh.exec_command(str("ifconfig " + this + " | grep 'inet' | cut -d: -f2 | awk '{print $2}'"))
        for line in stdout:
            edited = line.strip()
            if edited != '':
                ip.append(edited)
                ip.append(this)
    return ip
