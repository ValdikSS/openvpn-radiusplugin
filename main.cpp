/*
 *  radiusplugin -- An OpenVPN plugin for do radius authentication 
 *					and accounting.
 * 
 *  Copyright (C) 2005 EWE TEL GmbH/Ralf Luebben <ralfluebben@gmx.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
 
#include "openvpn-plugin.h"
#include "RadiusClass/RadiusPacket.h"
#include "radiusplugin.h"

#include <stdlib.h>
#include <stdio.h>


/** Only for testing the plugin!*/


int main (void)
{
	openvpn_plugin_handle_t context;
	//success* variables save return values of the functions
	int success1,success2,success3,success4,success5,success6,success7,success8,success9,success10,success11,success12;
	unsigned int type_mask=0;


	const char *env1[9];
	const char *env2[9];
	const char *env3[9];
	const char *env4[9];

	
	const char *argv[3];
	int type=5;

	
	
	env1[0]="username=user1";
	env1[1]="password=testing";
	env1[2]="verb=10";
	env1[3]="untrusted_ip=127.0.0.1";
	env1[4]="common_name=R-VPNGateway1";
	env1[5]="trusted_ip=127.0.0.1";
	env1[6]="ifconfig_pool_remote_ip=10.8.0.100";
	env1[7]="untrusted_port=111";
	env1[8]=NULL;
	
	env2[0]="username=user2";
	env2[1]="password=testing";
	env2[2]="verb=10";
	env2[3]="untrusted_ip=127.0.0.1";
	env2[4]="common_name=R-VPNGateway2";
	env2[5]="trusted_ip=127.0.0.1";
	env2[6]="ifconfig_pool_remote_ip=10.8.0.100";
	env2[7]="untrusted_port=111";
	env2[8]=NULL;
	
	env3[0]="username=user3";
	env3[1]="password=testing";
	env3[2]="verb=10";
	env3[3]="untrusted_ip=127.0.0.1";
	env3[4]="common_name=R-VPNGateway3";
	env3[5]="trusted_ip=127.0.0.1";
	env3[6]="ifconfig_pool_remote_ip=10.8.0.100";
	env3[7]="untrusted_port=111";
	env3[8]=NULL;
	
	env4[0]="username=user4";
	env4[1]="password=testing";
	env4[2]="verb=10";
	env4[3]="untrusted_ip=127.0.0.1";
	env4[4]="common_name=R-VPNGateway4";
	env4[5]="trusted_ip=127.0.0.1";
	env4[6]="ifconfig_pool_remote_ip=10.8.0.100";
	env4[7]="untrusted_port=111";
	env4[8]=NULL;
	
	argv[0]="radiusplugin.so";
	argv[1]="./radiusplugin.cnf";
	argv[2]=NULL;


	
	context=openvpn_plugin_open_v1(&type_mask,(const char **) argv,(const char **) env1);

	if (context==NULL)
	{
		return -1;	
	}
	//AUTH
	//env1
	success1=openvpn_plugin_func_v1(context, type, (const char **) argv, (const char **)env1);
	//sleep(1);
	//env2
	success2=openvpn_plugin_func_v1(context, type, (const char **) argv, (const char **)env2);
	//sleep(1);
	//env3
	success3=openvpn_plugin_func_v1(context, type, (const char **) argv, (const char **)env3);
	//sleep(1);
	//env4
	success4=openvpn_plugin_func_v1(context, type, (const char **) argv, (const char **)env4);
	//sleep(1);
	
	
	
	//CONNECT
	if (success1==0 && success2==0 && success3==0 && success4==0)
	{ 
		success5=openvpn_plugin_func_v1(context, 6, (const char **) argv, (const char **)env1);
		//sleep(1);
		success6=openvpn_plugin_func_v1(context, 6, (const char **) argv, (const char **)env2);
		//sleep(1);
		success7=openvpn_plugin_func_v1(context, 6, (const char **) argv, (const char **)env3);
		//sleep(1);
		success8=openvpn_plugin_func_v1(context, 6, (const char **) argv, (const char **)env4);
		//sleep(10);
	}
	
	cerr << "\n\nTurn off radius\n\n";
	sleep(5);	
		
		//rekeying AUTH
		//env1
		success1=openvpn_plugin_func_v1(context, type, (const char **) argv, (const char **)env1);
		//sleep(1);
		//env2
		success2=openvpn_plugin_func_v1(context, type, (const char **) argv, (const char **)env2);
		//sleep(1);
		//env3
		success3=openvpn_plugin_func_v1(context, type, (const char **) argv, (const char **)env3);
		//sleep(1);
		//env4
		success4=openvpn_plugin_func_v1(context, type, (const char **) argv, (const char **)env4);
		//sleep(1);
	

	if (success5==0 && success6==0 && success7==0 && success8==0)
	{
		//DISCONNECT
		success9=openvpn_plugin_func_v1(context, 7, (const char **) argv, (const char **)env1);
		//sleep(1);
		success10=openvpn_plugin_func_v1(context, 7, (const char **) argv, (const char **)env2);
		//sleep(1);
		success11=openvpn_plugin_func_v1(context, 7, (const char **) argv, (const char **)env3);
		//sleep(1);
		success12=openvpn_plugin_func_v1(context, 7, (const char **) argv, (const char **)env4);
	}
	
	openvpn_plugin_close_v1(context);
	if (success1==0 && success2==0 && success3==0 && success4==0 && success5==0 && success6==0 && success7==0 && success8==0 && success9==0 && success10==0 && success11==0 && success12==0 )
	{
		fprintf(stderr,"AUTH_OK");
	}
	else
	{
		fprintf(stderr,"FALSE");
	}

	
	return 0;
}
