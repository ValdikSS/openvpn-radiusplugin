# radiusplugin - An OpenVPN plugin for do RADIUS authentication and accounting

# Documentation
The documentation is done with doxygen.  
To generate the documentation execute `doxygen doxygen.conf` in the folder of the plugin.

# Installation
1. Requirements: the `libgcrypt` library.
2. Compile: see section [Compile](#compile)
3. Update OpenVPN server config: add `plugin /path/to/plugin/radiusplugin.so` as a single line at to the top of the file
4. Create a configfile for the plugin, see [radiusplugin.cnf](https://github.com/wannabehero/openvpn-radiusplugin/blob/b0ca05cd58d5d8157443634d44185b11088312eb/radiusplugin.cnf).  
If no path is set in the configfile of OpenVPN the plugin will read the file `/etc/openvpn/radiusplugin.cnf`  
The configuration is case-sensitive.
5. Update some configuration in the config file of the OpenVPN server:
- `status /var/log/openvpn/status.log 1` - The status, where the plugin reads the accounting information from.`
6. Update the config file of the OpenVPN client:
- `auth-user-pass` Set this for sending a username and password to the server (either promted or taken for the env)
7. If you use `auth_control_file` (>= OpenVPN 2.1 rc8), the plugin directory needs write permission to the OpenVPN directory or use the `--tmp-dir` option to define a directory for the files.
8. Maybe write your own script for vendor specific attributes (see section [Vendor specific attributes](#vendor-specific-attributes)).


## FREERADIUS example
```
user1  Cleartext-Password := "testing"
       Service-Type = Framed-User,
       Framed-IP-Netmask = 255.255.255.0,
       Framed-IP-Address = 10.8.0.33,
       Framed-Routing = Broadcast-Listen,
       Framed-Compression = Van-Jacobsen-TCP-IP,
       Framed-Route += "192.168.101.0/26 10.8.0.1/32 1",
       Framed-Route += "192.168.111.0/24 10.8.0.1/32 1",
       Framed-Route += "192.168.112.0/24 10.8.0.1/32 1",
       Acct-Interim-Interval=5,
       Ascend-Data-Rate=100,
       Ascend-Xmit-Rate=200,
       Framed-Protocol = PPP
```

The Framed-Route attribute must be in the format as shown above.


## Compile
```sh
$ make
```

*(tested with Debian on x86, for other architectures see section TROUBLESHOOTING)*


## RADIUS packets and OpenVPN events 
*see [OpenVPN Guide](https://openvpn.net/community-resources/management-interface/) for scripting and environmental variables*

OpenVPN event			|RADIUS PACKET               |Information
-------------           |------------                |------------
`auth-user-pass-verify` |ACCESS REQUEST              |parsed attributes (see below)
`client-connect`        |ACCOUNTING REQUEST (Start)	 |	
\-	                    |ACCOUNTING REQUEST (Update) |If the user had a acct interim interval attribute the update is sent periodically with this interval
`client-disconnect`     |ACCOUNTING REQUEST (Stop)   |\-

### RADIUS attributes which are beng parsed by the plugin
- Framed ip address
- Acct Interim Interval
- Framed Routes (only in following format, e.g.: "192.168.101.0/26 10.8.0.1/32 1")

## Other radius attributes
Reply Message → the text is forwarded to `stderr`

## Vendor specific attributes
If you want use vendor specific attributes the plugin can call your own program or script on the OpenVPN action `CLIENT-CONNECT` and `CLIENT-DISCONNECT`.
If you want to use this feature you have to specify the program and a named pipe for communication in the config file.  
[vsascript.pl](https://github.com/wannabehero/openvpn-radiusplugin/blob/181bf81b86ddb4d256f66827e6f198483c6660fa/vsascript.pl) shows an example.

## Limits
commonname of the certificate 256 characters 
routes entry from the radius server 50 characters

### Limits in RadiusConfig for the configfile:
(The limit is the length of the array minus 1!)
```
char serviceType[2];
char framedProtocol[2];
char nasPortType[2];
char nasIdentifier[128];
char nasIpAddress[16];
char p2p[16];
char subnet[16];
```


## Troubleshooting
- BSD:
	- RADIUS attributes FramedIP and FramedRoutes mandatory
	- RADIUS attribute FramedIP is ignored
	- Use gmake -f Makefile.bsd (maybe you have to adapt library and include path, it was tested for FreeBSD)

- Setting of Framed-Routes fails under BSD:
	- At the moment the plugin can only set the routes on Linux OSs.
	- The system call for "route ... " must be changed. Please contact me for a patch.
	- Newer version will integrate OS dependent calls. 

- OpenVPN hangs when a client connects:
	- Check OpenVPN config and check the OpenVPN log (debuglevel 7): 
		- The plugin needs following varibales from OpenVPN in ENVP-array:
			- username, password, untrusted_ip, common_name, untrusted_port, ifconfig_pool_remote_ip, verb
			- In some cases ifconfig_pool_remote_ip is missing (Depends on OpenVPN config).

- The radius packets are sent over the wrong interface:
	- Sometimes on multi interface machines with IPSec the operating system doesn't find the right interface.
	- Use the plugin from Magne J. Andreassen (it is for version 1.2a)

- The plugin writes client config files without any entry:
	- The plugin always writes the file for every connecting client, please set the ccd path 
		in the config file of the plugin to a existing dummy directory.
		
- Compiling fails on Solaris 10:
	- add following options: -lsocket -lnsl -lresolv
	
- Values for BytesIn/BytesOut are 0 in the accounting log of the RADIUS server:
	- Make sure that the status file of OpenVPN exists and the plugin can read it.
	- Use version 1 for the status file.

- Error at compiling: not initialised shared memory before the call to the MD5 function:
	- Make sure that you use libgrypt 1.2.0 or higher.

- Error at compiling: DBG: md_enable: algorithm -4195948 not available:
	- Make sure that you use libgrypt 1.2.0 or higher.

- The plugin can't write the auth_control_file.
        - The plugin needs write permission in the OpenVPN directory.


## Testing
**Attention:** Some values are hard coded in `main.cpp` testing, so you can get unexpected values when testing.
For example the `framedip` is always `10.8.0.100`, because it is read from the environment variable `ifconfig_pool_remote_ip`, which is passed to the plugin from OpenVPN!

All hard coded variabled:
```
env1[0]="username=user1";
env1[1]="password=testing";
env1[2]="verb=10";
env1[3]="untrusted_ip=127.0.0.1";
env1[4]="common_name=R-VPNGateway1";
env1[5]="trusted_ip=127.0.0.1";
env1[6]="ifconfig_pool_remote_ip=10.8.0.100";
```

compile for test with a main function:
```sh
g++ -Wall -o main AccountingProcess.cpp Exception.cpp PluginContext.cpp UserAuth.cpp AcctScheduler.cpp IpcSocket.cpp radiusplugin.cpp User.cpp AuthenticationProcess.cpp main.cpp UserAcct.cpp UserPlugin.cpp Config.cpp RadiusClass/RadiusAttribute.cpp RadiusClass/RadiusPacket.cpp RadiusClass/RadiusConfig.cpp RadiusClass/RadiusServer.cpp  RadiusClass/RadiusVendorSpecificAttribute.cpp -lgcrypt
```

# License
Copyright (C) 2005 EWE TEL GmbH/Ralf Luebben <ralfluebben@gmx.de>
 
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

# Note from the author
The plugin was developed during my diploma thesis for the EWETEL GmbH (www.ewetel.net). 
They main idea was to create a virtualized SSL-VPN with RADIUS support. 
The virtualization was done by XEN. 
At this place I would like to thank the people from EWETEL GmbH and EWE AG (www.ewe.de) 
who supported me with the required equipment, hardware 
and helped me with all my questions.

The plugin was developed and tested under Debian Sarge and OpenVPN 2.0 on x86-machines. 
