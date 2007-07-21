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


#include "Config.h"


/** The constructor The constructor initializes all char arrays with 0.
 */

Config::Config(void)
{
	
	this->usernameascommonname=false;
	this->clientcertnotrequired=false;
	this->ccdPath="";
	this->openvpnconfig="";
	this->vsanamedpipe="";
	this->vsascript="";
	memset(this->subnet,0,16);
	memset(this->p2p,0,16);
}

/** The constructor initializes all char arrays with 0. After the initialization
 * the configfile is parsed and the information which are
 * found are copied to the attributes.
 * @param configfile The name of the configfile.
 */

Config::Config(char * configfile)
{
	memset(this->subnet,0,16);
	memset(this->p2p,0,16);
	this->ccdPath="";
	this->openvpnconfig="";
	this->vsanamedpipe="";
	this->vsascript="";
	this->usernameascommonname=false;
	this->clientcertnotrequired=false;
	this->parseConfigFile(configfile);
	
}


/** The destructur clears the serverlist. */
Config::~Config(void)
{
	
	
}



/** The method parse the configfile for attributes and 
 * radius server, the attributes are copied to the
 * member variables.
 * @param configfile The name of the configfile.
 * @return An integer, 0 if everything is ok 
 * or PARSING_ERROR or BAD_FILE if something is wrong.*/
int Config::parseConfigFile(const char * configfile)
{
	string line;
	char tmp[50];

	
	ifstream file;
	file.open(configfile, ios::in);
	if (file.is_open())
	{
		while (file.eof()==false)
		{
			getline(file,line);
			this->deletechars(&line);
			if(line.empty()==false)
			{
			
				if (strncmp(line.c_str(),"subnet=",7)==0)
				{
					this->getValue(line.c_str(), tmp);
					strncpy(this->subnet,tmp,16);
				}
				if (strncmp(line.c_str(),"p2p=",4)==0)
				{
					this->getValue(line.c_str(), tmp);
					strncpy(this->p2p,tmp,16);
				}
				if (strncmp(line.c_str(),"vsascript=",10)==0)
				{
					this->getValue(line.c_str(), tmp);
					this->vsascript=tmp;
				}
				if (strncmp(line.c_str(),"vsanamedpipe=",13)==0)
				{
					this->getValue(line.c_str(), tmp);
					this->vsanamedpipe=tmp;
				}
							
				if (strncmp(line.c_str(),"OpenVPNConfig=",14)==0)
				{
					this->getValue(line.c_str(), tmp);
					this->openvpnconfig=tmp;
				}
			}
			
		}
		file.close();
		//open OpenVPN config
		ifstream file2;
		file2.open(this->openvpnconfig.c_str(), ios::in);
		if (file2.is_open())
		{
			while(file2.eof()==false)
			{
				getline(file2,line);
				this->deletechars(&line);
				if(line.empty()==false)
				{
					if (line == "client-cert-not-required")
					{
						this->clientcertnotrequired=true;
					}
					if (line == "username-as-common-name")
					{
						this->usernameascommonname=true;
					}
					if (string::size_type pos = line.find("client-config-dir") != string::npos)
					{
						line.erase(0, pos + 17);
						this->deletechars(&line);
						this->setCcdPath(line);
					}
					if (string::size_type pos = line.find("status") != string::npos)
					{
						line.erase(0, pos + 6);
						this->deletechars(&line);
						pos = line.find(" ");
						if (pos != string::npos) line.erase(pos);
						this->statusfile=line;
					}	
				}
			}
			file.close();
		}
		else
		{
			return BAD_FILE;
		}
	}
	else
	{
		return BAD_FILE;
	}
	return 0;
}
	
	
/** The method deletes chars from a string.
 * This is used to delete tabs, spaces, # and '\0'
 * from a string.
 * @param text The string which should be cleaned.
 */ 
void Config::deletechars(string * line)
{
	char const* delims = " \t\r\n\0";
    
   // trim leading whitespace
   string::size_type  pos = line->find_first_not_of(delims);
   if (pos != string::npos) line->erase(0,pos );

   // trim trailing whitespace
   pos  = line->find_last_not_of(delims); 
   if (pos != string::npos)  line->erase(pos+1);
   
   
   //trim whitespaces in line
   pos  = line->find_first_of(delims);
   while (pos != string::npos) 
   {
   	 line->erase(pos);
   	 pos  = line->find_first_of(delims);
   }
   
   // trim comments
   pos  = line->find_first_of("#");
   if (pos != string::npos) 
   {
   	line->erase(pos);
   }
}


/**The method finds the part of the string after the
 * '=' and puts it in the value.
 * @param text The string with the value.
 * @param value The value where to put the part of the string. */
void Config::getValue(const char * text, char * value)
{
	
	int i=0,j=0;
	while (text[i]!='=' && text[i]!='\0')
	{
		i++;
	}
	i++;
	while (text[i]!='\0')
	{
		value[j]=text[i];
		i++;
		j++;
	}
	value[j]='\0';
}




	
/** The getter methid for the client config dir (ccd).
 * @return A string to the ccd.
 */
string Config::getCcdPath(void)
{
	return this->ccdPath;
}


/** The setter method for the client config dir (ccd).
 * @param path A string to the ccd path.
 */
void Config::setCcdPath(string path)
{
	if(path[path.length()]!= '/')
	{
		path +='/';	
	}
	this->ccdPath=path;
}

/** Returns the path to the status file.
 * @param A string to path of the status file.
 */
string Config::getStatusFile(void)
{
	return this->statusfile;
}

/** The setter method for thepath to the statusfile (path + filename).
 * @param file A string of the filepath.
 */
void Config::setStatusFile(string file)
{
	
	this->statusfile=file;
}

/** The setter method for the nas ip address.
 * @param ip A string with ip address.
 */	
void Config::setSubnet(char * ip)
{
	strncpy(this->subnet,ip, 16);
}


/** The getter method for the nas ip address.
 * @return A pointer to the nas ipaddress.
 */
char * Config::getSubnet(void)
{
	return this->subnet;
}

/** The setter method for the p2p address.
 * @param ip A string with p2p address.
 */	
void Config::setP2p(char * ip)
{
	strncpy(this->p2p,ip, 16);
}


/** The getter method for the p2p address.
 * @return A pointer to the p2p address.
 */
char * Config::getP2p(void)
{
	return this->p2p;
}

/** The setter method for the vsascript.
 * @param script A path of the script.
 */	
void Config::setVsaScript(string script)
{
	this->vsascript=script;
}


/** The getter method for vsascript.
 * @return A pointer to the path of the script.
 */
string Config::getVsaScript(void)
{
	return this->vsascript;
}

/** The setter method for the usernameascommonname value.
 * @param b A boolean for option usernameascommonname.
 */	
void Config::setUsernameAsCommonname(bool b)
{
	this->usernameascommonname=b;
}


/** The getter method for the usernameascommonname value.
 * @return A boolean for option usernameascommonname.
 */
bool Config::getUsernameAsCommonname(void)
{
	return this->usernameascommonname;
}

/** The setter method for the vsanamedpipe.
 * @param script A path of the pipe.
 */	
void Config::setVsaNamedPipe(string pipe)
{
	this->vsanamedpipe=pipe;
}


/** The getter method for vsanamedpipe.
 * @return A pointer to the path of the pipe.
 */
string Config::getVsaNamedPipe(void)
{
	return this->vsanamedpipe;
}


/** The setter method for the clientcertnotrequired value.
 * @param b A boolean for option clientcertnotrequired.
 */	
void Config::setClientCertNotRequired(bool b)
{
	this->clientcertnotrequired=b;
}


/** The getter method for the clientcertnotrequired value.
 * @return A boolean for option clientcertnotrequired.
 */
bool Config::getClientCertNotRequired(void)
{
	return this->clientcertnotrequired;
}

/** The getter method for the path to the OpenVPN config
 * @return A string to the path.
 */
string Config::getOpenVPNConfig(void)
{
	return this->openvpnconfig;	
}

/** The setter method for the path to the OpenVPN config
 * @param conf Path to the config file.
 */
void Config::setOpenVPNConfig(string conf)
{
	this->openvpnconfig=conf;
}
