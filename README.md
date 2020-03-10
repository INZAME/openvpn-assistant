# OpenVPN Assitant

Old working version [here](https://github.com/INZAME/openvpn-assistant/releases).

Tested on Debian 8/9

## Getting Started

Download via git clone or regular download

### Prerequisites

Python version 3.6 or higher and some libs

```
paramiko
pyqt5
```

### How to

Just run main.py and folow screen instructions

```
1. Connect to your VDS or virtual machine
2. Complete installation process
3. Manage your ovpn profiles
4. Edit your existing server configuration
```

### Known issues

* Using *no logging* option while installing will not allow to start OpenVPN (can be activated later by hand)
* Checking crl.pem for revoked profiles not included(since i have no time to fix it)
