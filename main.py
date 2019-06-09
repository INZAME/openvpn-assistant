import sys
import login_design, main_design, setup_design, edit_design
import login_func
import os
import paramiko
import parsers
from base64 import b64encode, b64decode
from tempfile import NamedTemporaryFile
from PyQt5 import QtWidgets
from time import sleep
import io

class LoginWindow(QtWidgets.QMainWindow, login_design.Ui_ConnectWindow):
    def __init__(self, parent=None):
        super(LoginWindow, self).__init__(parent)
        self.setupUi(self)
        self.center()
        try:
            credit = open('login.ini', 'r')
            for line in credit:
                if line.startswith('login='):
                    self.login.setText(line.split('=')[1].rstrip('\n'))
                elif line.startswith('password='):
                    pswd = b64decode(line.split('=')[1].rstrip('\n'))
                    self.password.setText(pswd.decode('utf-8'))
                elif line.startswith('ip='):
                    self.ip.setText(line.split('=')[1].rstrip('\n'))
                elif line.startswith('port='):
                    self.port.setText(line.split('=')[1].rstrip('\n'))
        except Exception:
            pass
        try:
            rm_temp()
        except Exception:
            pass
        self.btnConnect.clicked.connect(self.connection)
        #self.ssh_connection = None
        #self.sftp_connection = None        
    
    def rm_temp(self):
        os.remove('./server.conf')
        os.remove('./vars')

    def center(self):
        qr = self.frameGeometry()
        cp = QtWidgets.QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def connection(self):
        install = False
        message = QtWidgets.QMessageBox.question(self, 'Continue?', "Do u want to connect?", QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)
        if message == QtWidgets.QMessageBox.Yes:
            ip_u = str(self.ip.text())
            login_u = self.login.text()
            port_u = int(self.port.text())
            password_u = self.password.text()
            if self.remember.isChecked():
                try:
                    os.remove('./login.ini')
                except Exception:
                    pass
                log = open('login.ini', 'w')
                crypted = b64encode(bytes(password_u, 'utf-8')).decode('utf-8')
                log.write(f'login={login_u}\n')
                log.write(f'password={crypted}\n')
                log.write(f'ip={ip_u}\n')
                log.write(f'port={port_u}')
                log.close()
            try:
                self.ssh_connection = login_func.auth(login_u, password_u, ip_u, port_u)
                self.sftp_connection = login_func.sftp(login_u, password_u, ip_u, port_u)
            except Exception as e:
                QtWidgets.QMessageBox.information(self, 'Error', f"{e}")
            else:
                QtWidgets.QMessageBox.information(self, 'Connection', f"Successfully connected.\nYour IP: {ip_u}:{port_u} \nYour user: {login_u}")
                try:  #UNCOMMENT AFTER DEBUG
                    self.sftp_connection.stat('/etc/openvpn/server.conf')
                except Exception as e:
                    first = QtWidgets.QMessageBox.question(self, 'First time?', 'Looks like there is no OpenVPN configured.\nStart installation manager?', QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.Yes)
                    if first == QtWidgets.QMessageBox.Yes:
                        self.ssh_connection.exec_command('apt install -y net-tools openvpn')
                        while not install:
                            try:
                                self.sftp_connection.stat('/etc/openvpn')
                                install = True
                            except Exception:
                                pass
                            else:
                                print('DEBUG: net-tools and openvpn installed!')
                        self.setup = SetupDialog(ssh=self.ssh_connection, sftp=self.sftp_connection)
                        self.setup.show()
                        self.close()
                else:
                    self.mainwin = MainWindow(ssh=self.ssh_connection, sftp=self.sftp_connection)
                    self.mainwin.show()
                    self.close()
        else:
            pass


class EditDialog(QtWidgets.QDialog, edit_design.Ui_Edit_Dialog):
    def __init__(self, ssh, sftp, parent=None):
        super(EditDialog, self).__init__(parent)
        self.setupUi(self)
        self.center()
        self.stream = ssh
        self.sftp_stream = sftp
        self.get_ip = parsers.get_ip(self.stream)
        self.ipEdit.setText(self.get_ip[0])
        self.finishButton.clicked.connect(self.editing)

    def center(self):
        qr = self.frameGeometry()
        cp = QtWidgets.QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def editing(self):
        config = []
        config.append(f'local {self.ipEdit.text()}')
        config.append(f'port {self.portEdit.text()}')
        config.append(f'proto {self.protoBox.currentText()}')
        config.extend(('dev tun', 'ca ca.crt', 'cert server.crt', 'key server.key',
                       ';crl-verify /etc/openvpn/easy-rsa/keys/crl.pem', 'dh dh2048.pem'))
        config.append(f'server {parsers.cidr_to_netmask(self.netipEdit.text())[0]} {parsers.cidr_to_netmask(self.netipEdit.text())[1]}')
        config.append('ifconfig-pool-persist ipp.txt')
        config.append('push "redirect-gateway def1"')
        if str(self.dnsBox.currentText()) == 'OpenNIC':
            config.append('dhcp-option DNS 91.217.137.37')
            config.append('dhcp-option DNS 172.104.136.243')
        elif str(self.dnsBox.currentText()) == 'Google':
            config.append('dhcp-option DNS 8.8.8.8')
            config.append('dhcp-option DNS 8.8.4.4')
        elif str(self.dnsBox.currentText()) == 'Yandex':
            config.append('dhcp-option DNS 77.88.8.8')
            config.append('dhcp-option DNS 77.88.8.1')
        config.extend(('keepalive 10 120', 'tls-server', 'auth SHA512', 'cipher AES-256-CBC',
                       'user nobody', 'group nogroup', 'persist-key', 'persist-tun'))
        if self.clientsBox.isChecked():
            config.append('client-to-client')
        if self.loggingBox.isChecked():
            config.extend(('status /dev/null', 'log /dev/null'))
        else:
            config.extend(('status openvpn-status.log', 'log openvpn.log', 'verb 3'))
        conf = io.open('./server.conf', 'w', newline='\n')
        for line in config:
            conf.write(line + '\n')
        conf.close()
        self.stream.exec_command('iptables -t nat -F; iptables -F')
        self.stream.exec_command('iptables -A FORWARD -i tun0 -j ACCEPT')
        self.stream.exec_command(f'iptables -A FORWARD -i tun0 -o {self.get_ip[1]} -m state --state RELATED,ESTABLISHED -j ACCEPT')
        self.stream.exec_command(f'iptables -A FORWARD -i {self.get_ip[1]} -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT')
        self.stream.exec_command(f'iptables -t nat -A POSTROUTING -s {self.netipEdit.text()} -o {self.get_ip[1]} -j SNAT --to-source {self.get_ip[0]}')
        self.stream.exec_command('export DEBIAN_FRONTEND=noninteractive; apt-get -yq install iptables-persistent')
        sleep(2)
        self.stream.exec_command('iptables-save > /etc/iptables.conf')
        self.stream.exec_command('iptables-save > /etc/iptables/rules.v4')
        self.stream.exec_command('echo "iptables-restore < /etc/iptables.conf" >> /etc/rc.local')
        self.sftp_stream.put('./server.conf', '/etc/openvpn/server.conf')
        os.remove('./server.conf')
        QtWidgets.QMessageBox.information(self, 'Succeed', 'Successfully copied configs!')


class SetupDialog(QtWidgets.QDialog, setup_design.Ui_Setup_Dialog):
    def __init__(self, ssh, sftp, parent=None):
        super(SetupDialog, self).__init__(parent)
        self.setupUi(self)
        self.center()
        self.stream = ssh
        self.sftp_stream = sftp
        self.get_ip = parsers.get_ip(self.stream)
        self.ipEdit.setText(self.get_ip[0])
        self.finishButton.clicked.connect(self.servconf)

    def center(self):
        qr = self.frameGeometry()
        cp = QtWidgets.QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())


    def servconf(self):
        created = False
        certs = False
        ready = False
        self.finishButton.setEnabled(False)
        try:
            os.remove('./vars')
        except Exception as e:
            pass
        self.stream.exec_command('mkdir /etc/openvpn/easy-rsa/; cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/; ln -s /etc/openvpn/easy-rsa/openssl-1.0.0.cnf /etc/openvpn/easy-rsa/openssl.cnf')
        while not created:
            try:
                self.sftp_stream.get('/etc/openvpn/easy-rsa/vars', './vars')
                created = True
            except FileNotFoundError:
                pass
            else:
                print('DEBUG: vars copied to local desktop')
        config = []
        config.append(f'local {self.ipEdit.text()}')
        config.append(f'port {self.portEdit.text()}')
        config.append(f'proto {self.protoBox.currentText()}')
        config.extend(('dev tun', 'ca ca.crt', 'cert server.crt', 'key server.key',
                       ';crl-verify /etc/openvpn/easy-rsa/keys/crl.pem', 'dh dh2048.pem'))
        config.append(f'server {parsers.cidr_to_netmask(self.netipEdit.text())[0]} {parsers.cidr_to_netmask(self.netipEdit.text())[1]}')
        config.append('ifconfig-pool-persist ipp.txt')
        config.append('push "redirect-gateway def1"')
        if str(self.dnsBox.currentText()) == 'OpenNIC':
            config.append('dhcp-option DNS 91.217.137.37')
            config.append('dhcp-option DNS 172.104.136.243')
        elif str(self.dnsBox.currentText()) == 'Google':
            config.append('dhcp-option DNS 8.8.8.8')
            config.append('dhcp-option DNS 8.8.4.4')
        elif str(self.dnsBox.currentText()) == 'Yandex':
            config.append('dhcp-option DNS 77.88.8.8')
            config.append('dhcp-option DNS 77.88.8.1')
        config.extend(('keepalive 10 120', 'tls-server', 'auth SHA512', 'cipher AES-256-CBC',
                       'user nobody', 'group nogroup', 'persist-key', 'persist-tun'))
        if self.clientsBox.isChecked():
            config.append('client-to-client')
        if self.loggingBox.isChecked():
            config.extend(('status /dev/null', 'log /dev/null'))
        else:
            config.extend(('status openvpn-status.log', 'log openvpn.log', 'verb 3'))
        conf = io.open('./server.conf', 'w', newline='\n')
        for line in config:
            conf.write(line + '\n')
        conf.close()
        self.sftp_stream.put('./server.conf', '/etc/openvpn/server.conf')

        with io.open('./vars', newline='\n') as fin, NamedTemporaryFile(dir='.', delete=False) as fout:
            for line in fin:
                if line.startswith("export KEY_COUNTRY="):
                    line = f'export KEY_COUNTRY="{self.countryEdit.text()}"\n'
                elif line.startswith("export KEY_PROVINCE="):
                    line = f'export KEY_PROVINCE="{self.provinceEdit.text()}"\n'
                elif line.startswith("export KEY_CITY="):
                    line = f'export KEY_CITY="{self.cityEdit.text()}"\n'
                elif line.startswith("export KEY_ORG="):
                    line = f'export KEY_ORG="{self.orgEdit.text()}"\n'
                elif line.startswith("export KEY_EMAIL="):
                    line = f'export KEY_EMAIL="{self.emailEdit.text()}"\n'
                fout.write(line.encode('utf8'))
        fin.close()
        os.remove('./vars')
        os.rename(fout.name, 'vars')
        self.sftp_stream.put('./vars', '/etc/openvpn/easy-rsa/vars')
        self.stream.exec_command('cd /etc/openvpn/easy-rsa/; source ./vars; ./clean-all; ./build-ca --batch; ./build-dh --batch; ./build-key-server --batch server;')
        generated = False
        while not generated:
            try:
                self.sftp_stream.stat('/etc/openvpn/easy-rsa/keys/server.key')
                generated = True
            except Exception:
                pass
            else:
                print('DEBUG: Certs generated!')
                sleep(1)
                self.stream.exec_command('cp /etc/openvpn/easy-rsa/keys/server.crt /etc/openvpn/server.crt; cp /etc/openvpn/easy-rsa/keys/server.key /etc/openvpn/server.key; cp /etc/openvpn/easy-rsa/keys/ca.crt /etc/openvpn/ca.crt; cp /etc/openvpn/easy-rsa/keys/dh2048.pem /etc/openvpn/dh2048.pem')
        while not ready:
            try:
                self.sftp_stream.stat('/etc/openvpn/dh2048.pem')
                ready = True
            except Exception:
                pass
            else:
                print('DEBUG: Certs successfully copied to ovpn dir!')
        self.stream.exec_command('iptables -A FORWARD -i tun0 -j ACCEPT')
        self.stream.exec_command(f'iptables -A FORWARD -i tun0 -o {self.get_ip[1]} -m state --state RELATED,ESTABLISHED -j ACCEPT')
        self.stream.exec_command(f'iptables -A FORWARD -i {self.get_ip[1]} -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT')
        self.stream.exec_command(f'iptables -t nat -A POSTROUTING -s {self.netipEdit.text()} -o {self.get_ip[1]} -j SNAT --to-source {self.get_ip[0]}')
        self.stream.exec_command('export DEBIAN_FRONTEND=noninteractive; apt-get -yq install iptables-persistent')
        sleep(2)
        self.stream.exec_command('iptables-save > /etc/iptables.conf')
        self.stream.exec_command('iptables-save > /etc/iptables/rules.v4')
        self.stream.exec_command('echo "iptables-restore < /etc/iptables.conf" >> /etc/rc.local')
        try:
            os.remove('./vars')
            os.remove('./server.conf')
        except Exception:
            pass
        sleep(2)
        QtWidgets.QMessageBox.information(self, 'Succeed', 'Successfully installed! Server gonna be restarted!')
        self.stream.exec_command('service openvpn restart')
        self.stream.exec_command('reboot')
        #self.mainwin = MainWindow(ssh=self.stream)
        #self.mainwin.show()
        self.close()


class MainWindow(QtWidgets.QMainWindow, main_design.Ui_MainWindow):
    def __init__(self, ssh, sftp, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setupUi(self)
        self.center()
        #self.justButton.clicked.connect(self.recieve_vars)
        self.stream = ssh
        self.sftp = sftp
        self.recieve_vars()
        self.ovpn_version()
        self.connLabel.setText(str(self.stream.get_transport().sock.getpeername()[0]))
        self.verLabel.setText(self.ovpn_version())
        self.usersLabel.setText(self.list_users())
        self.importButton_2.clicked.connect(self.editconf)
        self.dwnservButton.clicked.connect(self.dwn_selected)
        self.importButton.clicked.connect(self.importFile)
        self.dwnimpButton.clicked.connect(self.dwn_imported)
        self.revokeButton.clicked.connect(self.revoke_user)

    def revoke_user(self):
        selected = self.serverList.selectedItems()
        users = []
        for item in selected:
            if item.text() != 'server':
                users.append(item.text())
        try:
            for user in users:
                self.stream.exec_command(f'cd /etc/openvpn/easy-rsa; source ./vars; ./revoke-full {user}')
        except Exception as exc:
            QtWidgets.QMessageBox.information(self, 'Error', f'{exc}!')
        QtWidgets.QMessageBox.information(self, 'Done!', 'Users revoked!')
        self.usersLabel.setText(self.list_users())

    def editconf(self):
        self.editcnf = EditDialog(ssh=self.stream, sftp=self.sftp)
        self.editcnf.show()


    def ovpn_version(self):
        version = ''
        stdin, stdout, stderr = self.stream.exec_command('openvpn --version')
        for line in stdout:
            version = line.split()[1]
            break
        return version

    def list_users(self):
        self.serverList.selectAll()
        listItems = self.serverList.selectedItems()
        for item in listItems:
            self.serverList.takeItem(self.serverList.row(item))
        users = parsers.add_users(self.stream)
        for user in users:
            if user != 'server':
                self.serverList.addItem(user)
        return str(len(users))

    def importFile(self):
        fname = QtWidgets.QFileDialog.getOpenFileName(self, 'Open file', '.', options=QtWidgets.QFileDialog.Options())[0]
        if fname != '':
            self.importList.selectAll()
            listItems = self.importList.selectedItems()
            self.importList.takeItem(self.importList.row(listItems[0]))
            self.dwnimpButton.setEnabled(True)
            f = open(fname, 'r')
            for line in f:
                self.importList.addItem(line.rstrip('\n'))

    def center(self):
        qr = self.frameGeometry()
        cp = QtWidgets.QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def closeEvent(self, event):
        reply = QtWidgets.QMessageBox.question(self, 'Message', "Are you sure to quit?", QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)
        if reply == QtWidgets.QMessageBox.Yes:
            event.accept()
            self.stream.close()
        else:
            event.ignore()

    def dwn_imported(self):
        QtWidgets.QMessageBox.information(self, 'Downloading', 'Now gonna download selected users!')
        selected = self.importList.selectedItems()
        users = []
        for item in selected:
            if item.text() != 'server':
                users.append(item.text())
        try:
            parsers.download_profiles(self.stream, self.sftp, users)
        except Exception as exc:
            QtWidgets.QMessageBox.information(self, 'Error', f'{exc}!')
        QtWidgets.QMessageBox.information(self, 'Done!', 'Done! Check ur current directory!')
        self.usersLabel.setText(self.list_users())

    def dwn_selected(self):
        QtWidgets.QMessageBox.information(self, 'Downloading', 'Now gonna download selected users!')
        selected = self.serverList.selectedItems()
        users = []
        for item in selected:
            if item.text() != 'server':
                users.append(item.text())
        try:
            if len(users) > 1:
                QtWidgets.QMessageBox.information(self, 'Downloading', "There's more than 1 user.\nSubfolder 'profiles' will be created!")
                parsers.download_profiles(self.stream, self.sftp, users)
            else:
                parsers.download_profiles(self.stream, self.sftp, users, False)
        except Exception as exc:
            QtWidgets.QMessageBox.information(self, 'Error', f'{exc}!')
        QtWidgets.QMessageBox.information(self, 'Done!', 'Done! Check ur current directory!')

    def recieve_vars(self):
        down = False
        iface = ''
        while not down:
            try:
                sleep(2)
                iface = parsers.get_tun0(self.stream)
                self.tunLabel.setText(f'{iface[0]} ({iface[1]})')
                down = True
            except Exception:
                self.stream.exec_command('service openvpn restart')


def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle('Fusion')
    window = LoginWindow()
    # window = SetupDialog()
    window.show()
    app.exec_()


if __name__ == '__main__':
    main()
