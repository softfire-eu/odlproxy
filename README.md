  <img src="https://www.softfire.eu/wp-content/uploads/SoftFIRE_Logo_Fireball-300x300.png" width="120"/>

  Copyright © 2016-2018 [SoftFIRE](https://www.softfire.eu/) and [TU Berlin](http://www.av.tu-berlin.de/next_generation_networks/).
  Licensed under [Apache v2 License](http://www.apache.org/licenses/LICENSE-2.0).

# ODL Proxy
## Introduction
The purpose of odlproxy is to provide tenant/experiment access isolation for Opendaylight Openflow plugin restconf API.
After an experiment starts, three flow tables are assigned to an experimenter, so the experimenter can make restconf calls to the following urls:

http://[HOSTNAME]:[PORT]/restconf/config/opendaylight-inventory:nodes/node/openflow:[NODE_ID]/table/[TABLE_ID]/flow/[FLOW_ID]

Where TABLE_ID must be one of the TABLE_ID assigned to the experimenter.
Also the content of the requests is filtered, so requests that involve tables or openstack ports that are not owned by the experimenter are blocked, and the proxy returns a 403 Forbidden http response



## Installation

### 1. Requirements
Python 2.7 must be installed in your system. If both python27 and python3 are installed, make sure you run python27 binary.
The following dependencies must be installed with the following commands (make sure you run pip for python27):
```bash
pip install python-odlclient==0.0.1.dev13
pip install bottle==0.12.13
pip install openstacksdk==0.9.16
pip install pika==0.10.0
pip install futures==3.1.1
```
### 2. Copy source code
```bash
cd /FOLDER/WHERE/TO/INSTALL/ODLPROXY
cd /folder-where-to-install-odlproxy
git clone https://github.com/softfire-eu/odlproxy.git
```

### 3. Create folders
#### 3.1 log folder
```bash
sudo mkdir /var/log/odlproxy
sudo setfacl -m u:<user>:rwx /var/log/odlproxy/
```
#### 3.2 Persistence folder
```bash
sudo mkdir /var/lib/odlproxy
sudo setfacl -m u:<user>:rwx /var/lib/odlproxy/
```

### 4. Create config file
Default odlproxy config file is /etc/odlproxy/odlproxy.ini
So create it with the following 

Here below you find an example of odlproxy config file
```ini
[ODLPROXY]
#IP used to build the URL returned to the Experimenter, so it must be reacheable from the Experimenter and the ODLProxy must be binded on this address
PUBLIC_IP = 10.10.10.20
AUTH_SECRET = 90d82936f887a871df8cc82c1518a43e

[OPENSTACK]
OS_USERNAME = admin
OS_USERNAME_ID = ca81dc60f6c84f39b4568ca29f053e5f
OS_PASSWORD = adminpwd
OS_AUTH_URL = http://10.10.10.10/identity/v2.0/
OS_TENANT_ID = 11d54bf6419c4ec48fd0b267b11098d3
OS_PROJECT_ID = 11d54bf6419c4ec48fd0b267b11098d3

[ODL]
ODL_HOST = 10.10.10.10
ODL_PORT = 8181
ODL_USER = admin
ODL_PASS = adminpwd

[RABBIT]
RABBIT_HOST = 10.10.10.10
RABBIT_PORT = 5672
RABBIT_USER = admin
RABBIT_PASS = adminpwd
```
### 5. Logging
Copy the file from /folder-where-to-install-odlproxy//odlproxy/odlproxy.ini to /etc/odlproxy/odlproxy.ini
cp /folder-where-to-install-odlproxy//odlproxy/odlproxy.ini /etc/odlproxy/


## ODLProxy start

### 1. Run odlproxy
```bash
cd /FOLDER/WHERE/TO/INSTALL/ODLPROXY/odlproxy
python odlproxy_main.py &
```

### 2. Check odlproxy is running
After the previous command you should see the following output
```bash
INFO: eu.softfire.odl_proxy_api:250                 :  starting up
Bottle v0.12.13 server starting up (using WSGIRefServer())...
Listening on http://0.0.0.0:8001/
Hit Ctrl-C to quit.
```

You can also find the application log in
```bash
/var/log/odlproxy/odlproxy.log
```


## Issue tracker

Issues and bug reports should be posted to the GitHub Issue Tracker of this project.

# What is SoftFIRE?

SoftFIRE provides a set of technologies for building a federated experimental platform aimed at the construction and experimentation of services and functionalities built on top of NFV and SDN technologies.
The platform is a loose federation of already existing testbed owned and operated by distinct organizations for purposes of research and development.

SoftFIRE has three main objectives: supporting interoperability, programming and security of the federated testbed.
Supporting the programmability of the platform is then a major goal and it is the focus of the SoftFIRE’s Second Open Call.

## Licensing and distribution
Copyright © [2016-2018] SoftFIRE project

Licensed under the Apache License, Version 2.0 (the "License");

you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


