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
 
#ifndef _USER_ACCT_H_
#define _USER_ACCT_H_
#include <time.h>
#include <string.h>
#include "RadiusClass/RadiusPacket.h"
#include "openvpn-plugin.h"
#include "User.h"
#include "UserPlugin.h"
#include "PluginContext.h"


/** The class represents a user in the accounting background process. The class is
 * derived from the User class. This class defined additonal attributes
 * for accouting a user.*/

class UserAcct : public User
{
private:
	string sessionid;				/**< The sessionid of the user.*/
	unsigned long int bytesin;	/**< The received bytes.*/
	unsigned long int bytesout;	/**< The sent bytes.*/
	time_t nextupdate;			/**< The next update time.*/
	time_t starttime;			/**< The start time of the connection.*/
	
public:
	
	
	
	UserAcct();
	~UserAcct();
	
	string getSessionId(void);
	void setSessionId(string);
	
	int getServiceType(void);
	void setServiceType(int);
	
	unsigned long int getBytesIn(void);
	void setBytesIn(unsigned long int);
	
	unsigned long int getBytesOut(void);
	void setBytesOut(unsigned long int);
	
	time_t getStarttime(void);
	void setStarttime(time_t);
	
	time_t getNextUpdate(void);
	void setNextUpdate(time_t);
	
	
	UserAcct & operator=(const UserAcct &);
	
	UserAcct(const UserAcct &);
	
	int sendUpdatePacket(PluginContext *);
	int sendStartPacket(PluginContext *);
	int sendStopPacket(PluginContext *);
	void addSystemRoutes(PluginContext * );
	void delSystemRoutes(PluginContext * context);
	int deleteCcdFile(PluginContext *);
};

#endif //_USER_ACCT_H_
