# CHANGELOG

## v1.1a:
- Standard configfile: /etc/openvon/radiusplugin.cnf.
- #include <unistd.h> in IpcSocket.h, is needed for compiling on some systems. 
- Correct README: A configfile must set with "-c configfile".
- Correct fprintf statement in UserAuth.cpp (line 300).
- Set debug level from 7 to 5.

## v1.1.a (5.1.06):
- correct calculate of ipaddress for ifconfig-push in UserAuth::createCcdFile()
- FramedIpAddress-Attribute is set to the IP address OpenVPN is assigned to the client,
	the address is read from ENVP-Array with name ifconfig_pool_remote_ip and set to 
	FramedIpAddress-Attribute at client connect. (radiusplugin.cpp, openvpn_plugin_func_v1(), part: CLIENT_CONNECT)
- suppert for topology option (OpenVPN 2.0.1)
	- read from configfile parameters subnet, p2p
	- add parameters in config with getters, setters and modify constructors and destructor
	- modify UserAuth::createCcdFile to set the right topology option

## 1.2:
- use libgcrypt instead openssl (for gpl compability)
- checking of the authenticator field from received packets
- correct error on deleting users without an acct-interim-interval in AcctScheduler.cpp::findUser()
- send message to foreground process if no user was found (else the plugin hangs)

## 1.2a:
- correct error if a user connects again, if he is still known by the plugin, now the user can't reconnect if he is known by the plugin
- Change GPL text
- add COPYING file

## 1.2b:
- correct error: don't disconnect at rekeying/renegotiation

## 1.2c:
- new algorithm to generate Acct-Session-ID, so it should be unique ever, see createSessionID in radiusplugin.cpp

## 1.2d:
- option in OpenVPN config file is now: "plugin /etc/openvpn/radiusplugin.so [configfile]
- correct bug: close of configfile was missing

## 1.2e:
- use RadiusClass_v1.1a for more machine independance (big endian/little endian)
- use send()/recvInt() instead of sendCode()/recvCode() for internal socket communication

## 2.0:
new features
- support of vendor specific attributes with example perl script 
- support for OpenVPN options: dupliate-cn, client-cert-not-required, username-as-commonname
- comments allowd in config file
- parsing of OpenVPN config file for options (see radiusplugin.cnf)

fixed bugs
- crash on rekeying if no radius server respond
- framed ip is sent in access request packets if the client already has one (at rekeying), for dynamical key assignment through the radius server, so it will not send a new one
	- passwords and sharedsecret are shown as ****** in the logs

## 2.0a:
- fix error in IpcSocket.h,  
bad function name: void IpcSocket::recvBuf(User *) -> void recvBuf(User *);

## 2.0b:
- fixed datatypes from int to uint32_t/uint64_t to prevent overflows above 2^31
- added support for gigawords
- added a Makefile
- correct bug in parsing config files
- add new config variable overwriteccfiles, allows the plugin to overwrite client config files if set to true
- update some documentation
- correct parsing of ip address in RadiusAttribute.cpp in setValue for data type IPADDRESS
- update example config file
- use string for config parsing
- correct bug in Config.cpp: parameter status was detected wrong if parameter status-version parameter is used in OpenVPN config
- don't delete client config file at CLIENT-DISCONNECT it could be already a new file from a new AUTH-USER-PASS-VERIFY
- Fix segmentation fault in radiusplugin.cpp. The error occurs if an accounting request fails after a successful authentication.

## 2.0c:
- add IPv6 support (IPv6 patch for OpenVPN openvpn-2.1-udp6.patch)
- check if string/buffer length is zero in IpcSocket
- delete NAS port if authentication fails

## 2.0d_beta:
- add some headerfiles to avoid compiling errors on Fedora with gcc4
- close socket in radiuspacket.cpp on retries
- add parenthesize to avoid compiler warnings 

## 2.1:
- Support of OPENVPN_PLUGIN_FUNC_DEFERRED:  
The communication to the radius server for authentication is outsourced in a thread.  
If an auth control file is defined and `useauthcontrolfile=true` is defined in the config file of plugin the authentication is done the background.  
The OpenVPN process needs write permission in the OpenVPN directory.
- Timestamps are included in the debug information.
- Adapted to OPENVPN_PLUGIN_VERSION 2
- Internal key is now based on untrusted_ip and untrusted_before.
- Separated key for status file is added.
- Update password and username if the user (key) is already known. Before if the ip and port were the same and the timeout hasn't occurred the login will success. The update prevents against this behaviour. 
- Initialization of gcrypt library added.
- Rewrite ACF file when the user is authenticated.
- Include nested configfiles from main configfile.
- Add "\r" in the configfile parser, before the carriage return was ignored.
- Add support for RADIUS reply message, the output is sent to stderr 
- Only create the client-config file, if one of attributes for it is defined.
- Add NAS port number to the session id, it's definitely unique
- Acct-Session-Id added to Access-Request packet (RFC2866)

## 2.1a:
- Implement accounting only feature (option: accountingonly, default false)
- Implement non fatal accounting (failures during accounting let the user still connect) (nonfatalaccounting)

## 2.2
- Fix locks for operations with users waiting for authentication or accounting start

## 2.3:
- Allow to disable accounting