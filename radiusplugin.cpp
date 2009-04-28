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

//The callback functions of the plugin infrastructure.

#include "radiusplugin.h"


//define extern "C", so the c++ compiler generate a shared library
//which is compatible with c programms
extern "C"
{

	/** The function is needed by the OpenVpn plugin model. The funtion is called
	 * when OpenVpn starts. In this case here two background process are
	 * started. One for authentication and one for accounting. The communication
	 * between the processes is made via sockets.
	 * You need a background process for accounting, because the interval
	 * in which accounting information is sent to the radius server in undependent
	 * from the main OpenVpn-process, so it is done by another process which schedule
	 * the accounting intervals. This process holds his root rights and it can set and
	 * deletes routes in the system routing table.
	 * The authentication process is a own process, too. So there is clear separation
	 * and it is undependent from the openvpn process.
	 * @param The type of plugin, maybe client_connect, client_disconnect, user_auth_pass_verify...
	 * @param A list of arguments which are set in the configuration file of openvpn in plugin line.
	 * @param The list of enviromental variables, it is created by the OpenVpn-Process.
	 */


	//OPENVPN_EXPORT openvpn_plugin_handle_t
	//openvpn_plugin_open_v1 ( unsigned int *type_mask, const char *argv[], const char *envp[] )
	OPENVPN_PLUGIN_DEF openvpn_plugin_handle_t OPENVPN_PLUGIN_FUNC(openvpn_plugin_open_v2)(unsigned int *type_mask,
        const char *argv[],
        const char *envp[],
        struct openvpn_plugin_string_list **return_list)
        {
		pid_t 					pid;		/**<process number*/
		int 					fd_auth[2];	/**<An array for the socket pair of the authentication process.*/
		int 					fd_acct[2];	/**<An array for the socket pair of the accounting process.*/
		AccountingProcess   	Acct;		/**<The accounting background process object.*/
		AuthenticationProcess 	Auth; 		/**<The authentication background process object.*/
		PluginContext *context=NULL; 			/**<The context for this functions.*/


		//Create the context.
		context=new PluginContext;

		//list for additional arguments
		struct name_value_list name_value_list;


		//There must be one param, the name of the plugin file
		const int base_parms = 1;


		// Intercept the --auth-user-pass-verify, --client-connect and --client-disconnect callback.
		*type_mask = OPENVPN_PLUGIN_MASK ( OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY ) | OPENVPN_PLUGIN_MASK ( OPENVPN_PLUGIN_CLIENT_CONNECT ) | OPENVPN_PLUGIN_MASK ( OPENVPN_PLUGIN_CLIENT_DISCONNECT );

		// Get verbosity level from the environment.
		const char *verb_string = get_env ( "verb", envp );

		if ( verb_string )
			context->setVerbosity ( atoi ( verb_string ) );

		if ( DEBUG ( context->getVerbosity() ) )
			cerr << getTime() << "RADIUS-PLUGIN: Start AUTH-RADIUS-PLUGIN\n";


		// Make sure we have one string argument: the .so name.
		if ( string_array_len ( argv ) < base_parms )
		{
			cerr << getTime() << "RADIUS-PLUGIN: no .so name\n";
			goto error;
		}


		if ( DEBUG ( context->getVerbosity() ) )
			cerr << getTime() << "RADIUS-PLUGIN: Found "<<  string_array_len ( argv ) << " params.\n";


		// See if we have optional name/value pairs for
		// the plugin, this can only be the config file.
		// path (default: -c /etc/openvpn/radiusplugin.conf)
		name_value_list.len = 0;
		if ( string_array_len ( argv ) > base_parms )
		{
			if ( DEBUG ( context->getVerbosity() ) )
				cerr << getTime() << "RADIUS-PLUGIN: Find params.\n";

			//just a work around because argv[1] is the filename
			name_value_list.data[0].name = "-c";
			name_value_list.data[0].value = argv[1];

			if ( strncmp ( name_value_list.data[0].name,"-c",2 ) ==0 )
			{
				//see in ./RadiusClass/error.h for errornumbers
				//parse the radiusplugin config file
				cerr << getTime() << "RADIUS-PLUGIN: Configfile name: "<< name_value_list.data[0].value << ".\n";
				if ( context->radiusconf.parseConfigFile ( name_value_list.data[0].value ) !=0 or context->conf.parseConfigFile ( name_value_list.data[0].value ) !=0 )
				{
					cerr << getTime() << "RADIUS-PLUGIN: Bad config file or error in config.\n";
					goto error;
				}


			}
			else
			{
				cerr << getTime() << "RADIUS-PLUGIN: Bad argument for plugin.\n";
				goto error;
			}

		}
		else
		{
			//if there is no filename, use the default
			//parse the radiusplugin config file
			cerr << getTime() << "RADIUS-PLUGIN: Configfile name: /etc/openvpn/radiusplugin.cnf.\n";
			if ( context->radiusconf.parseConfigFile ( "/etc/openvpn/radiusplugin.cnf" ) !=0 or context->conf.parseConfigFile ( "/etc/openvpn/radiusplugin.cnf" ) !=0 )
			{
				cerr << getTime() << "RADIUS-PLUGIN: Bad config file or error in config.\n";
				goto error;
			}

		}


		// Make a socket for foreground and background processes
		// to communicate.
		//Authentication process:
		if ( socketpair ( PF_UNIX, SOCK_DGRAM, 0, fd_auth ) == -1 )
		{
			cerr << getTime() << "RADIUS-PLUGIN: socketpair call failed for authentication process\n";
			goto error;
		}
		//Accounting process:
		if ( socketpair ( PF_UNIX, SOCK_DGRAM, 0, fd_acct ) == -1 )
		{
			cerr << getTime() << "RADIUS-PLUGIN: socketpair call failed for accounting process\n";
			goto error;
		}


                
                
		//  Fork off the privileged processes.  It will remain privileged
		//  even after the foreground process drops its privileges.


		// 	Fork the authentication process
		pid = fork ();
		if ( pid )
		{
			// Foreground Process (Parent)
			int status;

			//save the process id
			context->setAuthPid ( pid );

			// close our copy of child's socket
			close ( fd_auth[1] );

			/* don't let future subprocesses inherit child socket */
			if ( fcntl ( fd_auth[0], F_SETFD, FD_CLOEXEC ) < 0 )
				cerr << getTime() << "RADIUS-PLUGIN: Set FD_CLOEXEC flag on socket file descriptor failed\n";

			if ( DEBUG ( context->getVerbosity() ) )
				cerr << getTime() << "RADIUS-PLUGIN: Start BACKGROUND Process for authentication with PID " << context->getAuthPid() << ".\n";

			//save the socket number in the context
			context->authsocketbackgr.setSocket ( fd_auth[0] );

			//wait for background child process to initialize */
			status = context->authsocketbackgr.recvInt();

			if ( status != RESPONSE_INIT_SUCCEEDED )
			{
				//set the socket to -1 if the initialization failed
				context->authsocketbackgr.setSocket ( -1 );
			}

			if ( DEBUG ( context->getVerbosity() ) )
				cerr << getTime() << "RADIUS-PLUGIN: Start AUTH-RADIUS-PLUGIN\n";
		}
		else
		{

			//Background Process

			// close all parent fds except our socket back to parent
			close_fds_except ( fd_auth[1] );

			// Ignore most signals (the parent will receive them)
			set_signals ();

			//save the socket number in the context
			context->authsocketforegr.setSocket ( fd_auth[1] );

			//start the backgroung event loop for accounting
			Auth.Authentication ( context );

			//close the socket
			close ( fd_auth[1] );

			//free the context of the background process
			delete context;

			exit ( 0 );
			return 0; // NOTREACHED
		}

		// 	Fork the accounting process
		pid = fork ();
		if ( pid )
		{
			// Foreground Process (Parent)
			int status;	//status if the background process

			//save the pid
			context->setAcctPid ( pid );

			if ( DEBUG ( context->getVerbosity() ) )
				cerr << getTime() << "RADIUS-PLUGIN: Start BACKGROUND Process for accounting with PID " << context->getAcctPid() << ".\n";

			// close our copy of child's socket */
			close ( fd_acct[1] );

			/* don't let future subprocesses inherit child socket */
			if ( fcntl ( fd_acct[0], F_SETFD, FD_CLOEXEC ) < 0 )
				cerr << getTime() << "RADIUS-PLUGIN: Set FD_CLOEXEC flag on socket file descriptor failed\n";

			//save the socket number in the context
			context->acctsocketbackgr.setSocket ( fd_acct[0] );

			// wait for background child process to initialize */
			status = context->acctsocketbackgr.recvInt();

			if ( status != RESPONSE_INIT_SUCCEEDED )
			{
				//set the socket to -1 if the initialization failed
				context->acctsocketbackgr.setSocket ( -1 );
			}

			if ( DEBUG ( context->getVerbosity() ) )
				cerr << getTime() << "RADIUS-PLUGIN: Start AUTH-RADIUS-PLUGIN\n";
		}
		else
		{

			//Background Process

			// close all parent fds except our socket back to parent
			close_fds_except ( fd_acct[1] );

			// Ignore most signals (the parent will receive them)
			set_signals ();

			if ( DEBUG ( context->getVerbosity() ) )
				cerr << getTime() << "RADIUS-PLUGIN: Start BACKGROUND Process for accounting\n";

			// save the socket in the context
			context->acctsocketforegr.setSocket ( fd_acct[1] );

			//start the backgroung event loop for accounting
			Acct.Accounting ( context );

			//close the socket
			close ( fd_acct[1] );

			//free the context of the background process
			delete context;
			exit ( 0 );
			return 0; // NOTREACHED
		}

		//return the context, this is used between the functions
		//openvpn_plugin_open_v1
		//openvpn_plugin_func_v1
		//openvpn_plugin_close_v1
		return ( openvpn_plugin_handle_t ) context;

	error:
		//delete the context
		if ( context )
			delete ( context );
		return NULL;
	}


	/** This funtion is called from the OpenVpn process everytime
	 * a event happens. The function handle the events (plugins)
	 * AUTH_USER_PASS_VERIFY, CLIENT_CONNECT, CLIENT_DISCONNECT.
	 * The function reads the information from the envriomental
	 * variable and sends the relevant information to the
	 * background processes.
	 * AUTH_USER_PASS_VERIFY: The user is authenticated by a radius server,
	 * if it succeeded the background sends back the framed ip, the routes and the acct_interim_interval
	 * for the user. Than the user is added to the context.
	 * CLIENT_CONNECT: The user is added to the accounting by
	 * sending the information to the background process.
	 * CLIENT_DISCONNECT: The user is deleted from the
	 * accounting by sending the information to the backgrund process.
	 * @param The handle which was allocated in the open function.
	 * @param The type of plugin, maybe client_conect, client_disconnect, auth_user_pass_verify
	 * @param A list of arguments which are set in the openvpn configuration file.
	 * @param The list of enviromental variables, it is created by the OpenVpn-Process.
	 * @return A interger with the status of the funtion (OPENVPN_PLUGIN_FUNC_SUCCESS or OPENVPN_PLUGIN_FUNC_ERROR).
	 */
        
	//OPENVPN_EXPORT int
	//openvpn_plugin_func_v1 ( openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[] )
        OPENVPN_PLUGIN_DEF int OPENVPN_PLUGIN_FUNC(openvpn_plugin_func_v2)
        (openvpn_plugin_handle_t handle,
            const int type,
              const char *argv[],
                const char *envp[],
                  void *per_client_context,
                    struct openvpn_plugin_string_list **return_list)
	{
		
                
                //restore the context which was created at the function openvpn_plugin_open_v1
		PluginContext *context = ( struct PluginContext * ) handle;

                if(context->getStartThread()==true)
                {
                  pthread_cond_init (context->getCondSend(), NULL);
                  pthread_mutex_init (context->getMutexSend(), NULL);
                  pthread_cond_init (context->getCondRecv(), NULL);
                  pthread_mutex_init (context->getMutexRecv(), NULL);

                  if(pthread_create(context->getThread(), NULL, &auth_user_pass_verify, (void *) context) != 0) 
                  {
                    cerr << getTime() << "RADIUS-PLUGIN: Thread creation failed.\n";
                    return OPENVPN_PLUGIN_FUNC_ERROR;
			//goto error;
                  }
                  context->setStartThread(false);
              
                } 

		UserPlugin 	*newuser=NULL; 	/**< A context for an new user.*/

		string common_name;			/**<A string for the common_name from the enviroment.*/
		string untrusted_ip;			/** untrusted_ip for ipv6 support **/


		///////////// OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY
		if ( type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY && ( context->authsocketbackgr.getSocket() ) >= 0 )
		{

			if ( DEBUG ( context->getVerbosity() ) )
			{
				cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY is called.\n";
			}
			//create a new user
			newuser=new UserPlugin();
                       

			//allocate the memory, don't care about the value
			try
			{
				if ( get_env ( "username", envp ) ==NULL )
				{
					throw Exception ( "RADIUS-PLUGIN: FOREGROUND: username is not defined\n" );
				}
				else if ( get_env ( "password", envp ) ==NULL )
				{
					throw Exception ( "RADIUS-PLUGIN: FOREGROUND: password is not defined\n" );
				}
				else if ( get_env ( "untrusted_ip", envp ) ==NULL && get_env ( "untrusted_ip6", envp ) ==NULL )
				{
					throw Exception ( "RADIUS-PLUGIN: FOREGROUND: untrusted_ip and untrusted_ip6 is not defined\n" );
				}
				else if ( get_env ( "common_name", envp ) ==NULL )
				{
					if ( context->conf.getClientCertNotRequired() == false )
					{
						throw Exception ( "RADIUS-PLUGIN: FOREGROUND: common_name is not defined\n" );
					}
				}
				else if ( get_env ( "untrusted_port", envp ) ==NULL )
				{
					throw Exception ( "RADIUS-PLUGIN: FOREGROUND: untrusted_port is not defined\n" );
				}
                                
                                if (get_env ( "auth_control_file", envp ) != NULL)
                                {
                                  newuser->setAuthControlFile( get_env ( "auth_control_file", envp ) );
                                }
                    
				// get username, password, unrusted_ip and common_name from envp string array
				newuser->setUsername ( get_env ( "username", envp ) );
				newuser->setPassword ( get_env ( "password", envp ) );

				// it's ipv4
				if ( get_env ( "untrusted_ip", envp ) !=NULL )
				{
					untrusted_ip = get_env ( "untrusted_ip", envp );
				}
				// it's ipv6
				else
				{
					untrusted_ip = get_env ( "untrusted_ip6", envp );
				}
				newuser->setCallingStationId ( untrusted_ip );
				//for OpenVPN option client cert not required, common_name is "UNDEF", see status.log

				if ( get_env ( "common_name", envp ) !=NULL )
				{
					newuser->setCommonname ( get_env ( "common_name", envp ) );
				}
				
                                //rewrite the username if OpenVPN use the option username-as-comon-name
				if ( context->conf.getUsernameAsCommonname() == true )
				{
					if ( DEBUG ( context->getVerbosity() ) ) cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Commonname set to Username\n";
					newuser->setCommonname ( get_env ( "username", envp ) );
				}


				newuser->setUntrustedPort ( get_env ( "untrusted_port", envp ) );
				newuser->setStatusFileKey(newuser->getCommonname() +string ( "," ) + untrusted_ip + string ( ":" ) + get_env ( "untrusted_port", envp ) );
                                newuser->setKey(untrusted_ip + string ( ":" ) + get_env ( "untrusted_port", envp ) );
                                if ( DEBUG ( context->getVerbosity() ) ) cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Key: " << newuser->getKey() << ".\n";
                               
                                if (newuser->getAuthControlFile().length() > 0 && context->conf.getUseAuthControlFile())
                                {
                                  pthread_mutex_lock(context->getMutexSend());
                                  context->addNewUser(newuser);
                                  pthread_cond_signal( context->getCondSend( ));
                                  pthread_mutex_unlock (context->getMutexSend());
                                  return OPENVPN_PLUGIN_FUNC_DEFERRED;  
                                }
                                else
                                {
                                  pthread_mutex_lock(context->getMutexSend());
                                  context->addNewUser(newuser);
                                  pthread_cond_signal( context->getCondSend( ));
                                  pthread_mutex_unlock (context->getMutexSend());
                                  pthread_cond_wait( context->getCondRecv(), context->getMutexRecv());
                                  return context->getResult();
                                }


			}
			catch ( Exception &e )
			{
				cerr << getTime() << e;
			}
			catch ( ... )
			{
				cerr << getTime() << "Unknown Exception!";

			}
			return OPENVPN_PLUGIN_FUNC_ERROR;
			/////////////////////////// CLIENT_CONNECT
		}
		if ( type == OPENVPN_PLUGIN_CLIENT_CONNECT && context->acctsocketbackgr.getSocket() >= 0 )
		{


			if ( DEBUG ( context->getVerbosity() ) )
			{
				cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: OPENVPN_PLUGIN_CLIENT_CONNECT is called.\n";
			}

			try
			{
				if ( get_env ( "untrusted_ip", envp ) ==NULL &&  get_env ( "untrusted_ip6", envp ) ==NULL )
				{
					throw Exception ( "RADIUS-PLUGIN: FOREGROUND: untrusted_ip and untrusted_ip6 is not defined\n" );
				}
				else if ( get_env ( "common_name", envp ) ==NULL )
				{
					if ( context->conf.getClientCertNotRequired() == false )
					{
						throw Exception ( "RADIUS-PLUGIN: FOREGROUND: common_name is not defined\n" );
					}
				}
				else if ( get_env ( "untrusted_port", envp ) ==NULL )
				{
					throw Exception ( "RADIUS-PLUGIN: FOREGROUND: untrusted_port is not defined\n" );
				}
				else if ( get_env ( "ifconfig_pool_remote_ip", envp ) ==NULL )
				{
					throw Exception ( "RADIUS-PLUGIN: FOREGROUND: ifconfig_pool_remote_ip is not defined\n" );
				}
				//get username, password and trusted_ip from envp string array
				//for OpenVPN option client cert not required, common_name is "UNDEF", see status.log

				if ( get_env ( "untrusted_ip", envp ) !=NULL )
				{
					untrusted_ip = get_env ( "untrusted_ip", envp );
				}
				else
				{
					untrusted_ip = get_env ( "untrusted_ip6", envp );
				}

				if ( get_env ( "common_name", envp ) !=NULL )
				{
					common_name=get_env ( "common_name", envp );
				}
				else
				{
					common_name="UNDEF";
				}
				//rewrite the username if OpenVPN use the option username-as-comon-name
				if ( context->conf.getUsernameAsCommonname() == true )
				{
					common_name=get_env ( "username", envp );
				}
				//get the IP assigned to the client

				const char *ifconfig_pool_remote_ip=get_env ( "ifconfig_pool_remote_ip", envp );
				//find the user in the context, he was added at the OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY
				//string key=common_name + string ( "," ) +untrusted_ip+string ( ":" ) + string ( get_env ( "untrusted_port", envp ) );
                                string key=untrusted_ip+string ( ":" ) + string ( get_env ( "untrusted_port", envp ) );
                                if ( DEBUG ( context->getVerbosity() ) ){
                                        cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Key: " << key << ".\n";
				}
                                newuser=context->findUser(key);
                                if(newuser == NULL)
                                {
                                  
                                  throw Exception ( "RADIUS-PLUGIN: FOREGROUND: User should be accounted but is unknown, should never happen.\n" );
                                }

				//set the assigned ip as Framed-IP-Attribute of the user (see RFC2866, chapter 4.1 for more information)
				newuser->setFramedIp ( string ( ifconfig_pool_remote_ip ) );
				if ( DEBUG ( context->getVerbosity() ) )
					cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Set FramedIP to the IP (" << newuser->getFramedIp() << ") OpenVPN assigned to the user " << newuser->getUsername() << "\n";
				//the user must be there and must be authenticated but not accounted
				// isAccounted and isAuthenticated is true it is client connect for renegotiation, the user is already in the accounting process
				if ( newuser!=NULL && newuser->isAccounted() ==false && newuser->isAuthenticated() ==true )
				{
					//transform the integers to strings to send them over the socket

					if ( DEBUG ( context->getVerbosity() ) )
						cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Add user for accounting: username: " << newuser->getUsername() << ", commonname: " << newuser->getCommonname() << "\n";

					//send information to the background process
					context->acctsocketbackgr.send ( ADD_USER );
					context->acctsocketbackgr.send ( newuser->getUsername() );
					context->acctsocketbackgr.send ( newuser->getSessionId() );
					context->acctsocketbackgr.send ( newuser->getPortnumber() );
					context->acctsocketbackgr.send ( newuser->getCallingStationId() );
					context->acctsocketbackgr.send ( newuser->getFramedIp() );
					context->acctsocketbackgr.send ( newuser->getCommonname() );
					context->acctsocketbackgr.send ( newuser->getAcctInterimInterval() );
					context->acctsocketbackgr.send ( newuser->getFramedRoutes() );
					context->acctsocketbackgr.send ( newuser->getKey() );
                                        context->acctsocketbackgr.send ( newuser->getStatusFileKey());
					context->acctsocketbackgr.send ( newuser->getUntrustedPort() );
					context->acctsocketbackgr.send ( newuser->getVsaBuf(), newuser->getVsaBufLen() );
					//get the response
					const int status = context->acctsocketbackgr.recvInt();
					if ( status == RESPONSE_SUCCEEDED )
					{
						newuser->setAccounted ( true );

						if ( DEBUG ( context->getVerbosity() ) )
							cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Accouting succeeded!\n";

						return OPENVPN_PLUGIN_FUNC_SUCCESS;
					}
					else
					{
						//free the nasport
						context->delNasPort ( newuser->getPortnumber() );
						string error;
						error="RADIUS-PLUGIN: FOREGROUND: Accounting failed for user:";
						error+=newuser->getUsername();
						error+="!\n";
						//delete user from context
						context->delUser ( newuser->getKey() );
						throw Exception ( error );
					}
				}
				else
				{

					string error;
					error="RADIUS-PLUGIN: FOREGROUND: No user with this commonname or he is already authenticated: ";
					error+=common_name;
					error+="!\n";
					throw Exception ( error );

				}
			}
			catch ( Exception &e )
			{
				cerr << getTime() << e;
			}
			catch ( ... )
			{
				cerr << getTime() << "Unknown Exception!";

			}
			return OPENVPN_PLUGIN_FUNC_ERROR;
		}

		///////////////////////// OPENVPN_PLUGIN_CLIENT_DISCONNECT

		if ( type == OPENVPN_PLUGIN_CLIENT_DISCONNECT && context->acctsocketbackgr.getSocket() >= 0 )
		{


			if ( DEBUG ( context->getVerbosity() ) )
			{
				cerr << getTime() << "\n\nRADIUS-PLUGIN: FOREGROUND: OPENVPN_PLUGIN_CLIENT_DISCONNECT is called.\n";
			}
			try
			{
				if ( get_env ( "untrusted_ip", envp ) ==NULL && get_env ( "untrusted_ip6", envp ) ==NULL )
				{
					throw Exception ( "RADIUS-PLUGIN: FOREGROUND: untrusted_ip and untrusted_ip6 is not defined\n" );
				}
				else if ( get_env ( "common_name", envp ) ==NULL )
				{
					if ( context->conf.getClientCertNotRequired() == false )
					{
						throw Exception ( "RADIUS-PLUGIN: FOREGROUND: common_name is not defined\n" );
					}
				}
				else if ( get_env ( "untrusted_port", envp ) ==NULL )
				{
					throw Exception ( "RADIUS-PLUGIN: FOREGROUND: untrusted_port is not defined\n" );
				}

				if ( get_env ( "untrusted_ip", envp ) !=NULL )
				{
					untrusted_ip = get_env ( "untrusted_ip", envp );
				}
				else
				{
					untrusted_ip = get_env ( "untrusted_ip6", envp );
				}



				// get common_name from envp string array, if you don't use certificates it is "UNDEF"
				// get username, password and trusted_ip from envp string array
				//for OpenVPN option client cert not required, common_name is "UNDEF", see status.log
				if ( get_env ( "common_name", envp ) !=NULL )
				{
					common_name=get_env ( "common_name", envp );
				}
				else
				{
					common_name="UNDEF";
				}
				//rewrite the username if OpenVPN use the option username-as-comon-name
				if ( context->conf.getUsernameAsCommonname() == true )
				{
					common_name=get_env ( "username", envp );
				}

				//find the user in the context
				//newuser=context->findUser ( common_name + string ( "," ) + untrusted_ip + string ( ":" ) + string ( get_env ( "untrusted_port", envp ) ) );
                                newuser=context->findUser ( untrusted_ip + string ( ":" ) + string ( get_env ( "untrusted_port", envp ) ) );

				if ( newuser!=NULL )
				{

					if ( DEBUG ( context->getVerbosity() ) )
						cerr << getTime() <<  "RADIUS-PLUGIN: FOREGROUND: Delete user for accounting: commonname: " << newuser->getKey() << "\n";


					//send the information to the background process
					context->acctsocketbackgr.send ( DEL_USER );
					context->acctsocketbackgr.send ( newuser->getKey() );

					//get the responce
					const int status = context->acctsocketbackgr.recvInt();
					if ( status == RESPONSE_SUCCEEDED )
					{
						if ( DEBUG ( context->getVerbosity() ) )
							cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Accouting for user with key" << newuser->getKey()  << " stopped!\n";

						//free the nasport
						context->delNasPort ( newuser->getPortnumber() );

						//delete user from context
						context->delUser ( newuser->getKey() );
						return OPENVPN_PLUGIN_FUNC_SUCCESS;
					}
					else
					{
						//free the nasport
						context->delNasPort ( newuser->getPortnumber() );

						//delete user from context
						context->delUser ( newuser->getKey() );
						cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Error in ACCT Background Process!\n";

					}

				}
				else
				{
					throw Exception ( "No user with this common_name!\n" );

				}
			}
			catch ( Exception &e )
			{
				cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND:" << e;
			}
			catch ( ... )
			{
				cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND:" << "Unknown Exception!\n";
			}

		}

		return OPENVPN_PLUGIN_FUNC_ERROR;
	}


	/** The function is called when the OpenVpn process exits.
	 * A exit command is send to the background processes and
	 * the context is freed which was allocted in the open function.
	 * @param The handle which was allocated in the open function.
	 */

	OPENVPN_PLUGIN_DEF void OPENVPN_PLUGIN_FUNC(openvpn_plugin_close_v1)(openvpn_plugin_handle_t handle)
	{
		//restore the context
		PluginContext *context = ( PluginContext * ) handle;

		if ( DEBUG ( context->getVerbosity() ) )
			cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: close\n";


		if ( context->authsocketbackgr.getSocket() >= 0 )
		{
			if ( DEBUG ( context->getVerbosity() ) )
				cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: close auth background process\n";

			//tell background process to exit
			try
			{
				context->authsocketbackgr.send ( COMMAND_EXIT );
			}
			catch ( Exception &e )
			{
				cerr << getTime() << e;
			}

			// wait for background process to exit
			if ( context->getAuthPid() > 0 )
				waitpid ( context->getAuthPid(), NULL, 0 );

		}

		if ( context->acctsocketbackgr.getSocket() >= 0 )
		{
			if ( DEBUG ( context->getVerbosity() ) )
				cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: close acct background process.\n";

			//tell background process to exit
			try
			{
				context->acctsocketbackgr.send ( COMMAND_EXIT );
			}
			catch ( Exception &e )
			{
				cerr << getTime() << e;
			}

			// wait for background process to exit
			if ( context->getAcctPid() > 0 )
				waitpid ( context->getAcctPid(), NULL, 0 );

		}
                
                //stop the thread
                pthread_mutex_lock(context->getMutexSend());
                context->setStopThread(true);
                pthread_cond_signal( context->getCondSend( ));
                pthread_mutex_unlock (context->getMutexSend());
		//wait for the thread to exit
                pthread_join(*context->getThread(),NULL);
                //free the context
		delete context;
                 
	}


}


/** Original function from the openvpn auth-pam plugin.
 * Given an environmental variable name, search
 * the envp array for its value, returning it
 * if found or NULL otherwise.
 * A field in the envp-array looks like: name=user1
 * @param The name of the variable.
 * @param The array with the enviromental variables.
 * @return A poniter to the variable value or NULL, if the varaible was not found.
 */
const char * get_env ( const char *name, const char *envp[] )
{
	if ( envp )
	{
		int i;
		const int namelen = strlen ( name );

		for ( i = 0; envp[i]; ++i )
		{
			//compare the enviromental names
			if ( !strncmp ( envp[i], name, namelen ) )
			{
				//if the varibale is found
				const char *cp = envp[i] + namelen;
				//return the value behind the =
				if ( *cp == '=' )
					return cp + 1;
			}
		}
	}
	return NULL;
}



/** Original function from the openvpn auth-pam plugin.
 * Return the length of a string array.
 * @param Array
 * @return The length of the arry.
 */
int string_array_len ( const char *array[] )
{
	int i = 0;
	if ( array )
	{
		while ( array[i] )
			++i;
	}
	return i;
}

/** Original function from the openvpn auth-pam plugin.
 * Close most of parent's fds.
 * Keep stdin/stdout/stderr, plus one
 * other fd which is presumed to be
 * our pipe back to parent.
 * Admittedly, a bit of a kludge,
 * but posix doesn't give us a kind
 * of FD_CLOEXEC which will stop
 * fds from crossing a fork().
 * @param The socket number which should not be closed.
 */
void close_fds_except ( int keep )
{
	int i;
	closelog ();
	for ( i = 3; i <= 100; ++i )
	{
		if ( i != keep )
			close ( i );
	}
}

/** Original function from the openvpn auth-pam plugin.
 * Usually we ignore signals, because our parent will
 * deal with them.
 */
void set_signals ( void )
{
	signal ( SIGTERM, SIG_DFL );

	signal ( SIGINT, SIG_IGN );
	signal ( SIGHUP, SIG_IGN );
	signal ( SIGUSR1, SIG_IGN );
	signal ( SIGUSR2, SIG_IGN );
	signal ( SIGPIPE, SIG_IGN );
}


/** The function creates a md5 hash string as session ID over
 * - user->commonname
 * - user->callingstationid
 * - user->untrustedport
 * - time string from ctime(...)
 * @param A pointer to the user for which the session ID is created.
 * @return A string with the hash.
 */
string createSessionId ( UserPlugin * user )
{
	unsigned char digest[16];
	char text[33]; 	//The digest.
	gcry_md_hd_t  context;						//the hash context
	int i;
	time_t rawtime;
	string strtime;
	memset ( digest,0,16 );
	//build the hash
	gcry_md_open ( &context, GCRY_MD_MD5, 0 );
	gcry_md_write ( context, user->getCommonname().c_str(), user->getCommonname().length() );
	gcry_md_write ( context, user->getCallingStationId().c_str(), user->getCallingStationId().length() );
	gcry_md_write ( context, user->getUntrustedPort().c_str(), user->getUntrustedPort().length() );
	time ( &rawtime );
	strtime=ctime ( &rawtime );
	gcry_md_write ( context, strtime.c_str(),strtime.length() );
	memcpy ( digest, gcry_md_read ( context, GCRY_MD_MD5 ), 16 );
	gcry_md_close ( context );


	unsigned int h,l;
	char *p=text;
	unsigned char *c=digest;
	for ( i=0; i<16; i++ )
	{
		h = *c / 16;
		l = *c % 16;
		c++;
		*p++ = "01234567890ABCDEF"[h];
		*p++ = "01234567890ABCDEF"[l];
	}
	text[32]='\0';
	return string ( text );
}


/** The function implements the thread for authentication. If the auth_control_file is specified the thread writes the results in the  
 * auth_control_file, if the file is not specified the thread forward the OPENVPN_PLUGIN_FUNC_SUCCESS or OPENVPN_PLUGIN_FUNC_ERROR 
 * to the main process.
 * @param _context The context pointer from OpenVPN.
 */
 
void  * auth_user_pass_verify(void * c)
{
        cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Auth_user_pass_verify thread started.\n";
        PluginContext * context = (PluginContext *) c;

        //main thread loop for authentication
        while(!context->getStopThread())
        {
          if(context->UserWaitingtoAuth()==false)
          {
            if ( DEBUG ( context->getVerbosity() ) ) cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Waiting for new user.\n";
            pthread_cond_wait(context->getCondSend(),context->getMutexSend());
            if(context->getStopThread())
            { 
              cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Stop signal received.\n";  
              break;
            }
          }
          if ( DEBUG ( context->getVerbosity() ) ) cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: New user from OpenVPN!\n";
          //is the user already known?
          UserPlugin	*olduser=NULL;	/**<A context for an already known user.*/
          UserPlugin	*newuser=NULL;	/**<A context for the new user.*/
          newuser = context->getNewUser();
          olduser=context->findUser ( newuser->getKey() );
          
          if ( olduser!=NULL )  //probably key renegotiation
          {
                  if ( DEBUG ( context->getVerbosity() ) )
                          cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Renegotiation: username: "<< olduser->getUsername()
                          << "\nRADIUS-PLUGIN: FOREGROUND THREAD:\t olduser ip: " << olduser->getCallingStationId()
                          << "\nRADIUS-PLUGIN: FOREGROUND THREAD:\t olduser port: " << olduser->getUntrustedPort()
                          << "\nRADIUS-PLUGIN: FOREGROUND THREAD:\t olduser FramedIP: " << olduser->getFramedIp()
                          << "\nRADIUS-PLUGIN: FOREGROUND THREAD:\t newuser ip: " << olduser->getCallingStationId()
                          << "\nRADIUS-PLUGIN: FOREGROUND THREAD:\t newuser port: " << olduser->getUntrustedPort()
                          << "\n";
                  cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: isAuthenticated()" <<  olduser->isAuthenticated();
                  cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: isAcct()" <<  olduser->isAccounted();
                  //delete the newuser and use the olduser
                  delete newuser;
                  newuser=olduser;
                  //TODO: for threading check if the user is already accounted (He must be for renegotiation)
          }
          else //new user for authentication, no renegotiation
          {
                  newuser->setPortnumber ( context->addNasPort() );
                  newuser->setSessionId ( createSessionId ( newuser ) );
                  //add the user to the context
                  context->addUser(newuser);
          }
  
          if ( DEBUG ( context->getVerbosity() ) )
                  cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: New user: username: "<< newuser->getUsername()  <<", password: *****"
                  << ", newuser ip: " << newuser->getCallingStationId()
                  << ", newuser port: " << newuser->getUntrustedPort() << " .\n";
  
          //there must be a username
          if ( newuser->getUsername().size() > 0 )  //&& olduser==NULL)
          {
                  //send the informations to the backgorund process
                  context->authsocketbackgr.send ( COMMAND_VERIFY );
                  context->authsocketbackgr.send ( newuser->getUsername() );
                  context->authsocketbackgr.send ( newuser->getPassword() );
                  context->authsocketbackgr.send ( newuser->getPortnumber() );
                  context->authsocketbackgr.send ( newuser->getCallingStationId() );
                  context->authsocketbackgr.send ( newuser->getCommonname() );
                  context->authsocketbackgr.send ( newuser->getFramedIp() );
  
                  //get the response
                  const int status = context->authsocketbackgr.recvInt();
                  if ( status == RESPONSE_SUCCEEDED )
                  {
                          if ( DEBUG ( context->getVerbosity() ) )
                                  cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Authentication succeeded!\n";
  
                          //get the routes from background process
                          newuser->setFramedRoutes ( context->authsocketbackgr.recvStr() );
                          if ( DEBUG ( context->getVerbosity() ) )
                                  cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Received routes for user: "<< newuser->getFramedRoutes() << ".\n";
                          //get the framed ip
                          newuser->setFramedIp ( context->authsocketbackgr.recvStr() );
                          if ( DEBUG ( context->getVerbosity() ) )
                                  cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Received framed ip for user: "<< newuser->getFramedIp() << ".\n";
  
  
                          // get the interval from the background process
                          newuser->setAcctInterimInterval ( context->authsocketbackgr.recvInt() );
                          if ( DEBUG ( context->getVerbosity() ) )
                                  cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Receive acctinteriminterval " << newuser->getAcctInterimInterval() <<" sec from backgroundprocess.\n";
  
                          //clear the buffer if it isn't empty
                          if ( newuser->getVsaBuf() !=NULL )
                          {
                                  delete [] newuser->getVsaBuf();
                                  newuser->setVsaBuf ( NULL );
                          }
                          // get the vendor specific attribute buffer from the background process
                          context->authsocketbackgr.recvBuf ( newuser );
  
                          //add the user to the context
                          // if the is already in the map, addUser will throw an exception
                          // only add the user if he it not known already
                          
                          if ( newuser->isAuthenticated() ==false )
                          {
                                  cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Add user to map.\n";
                                  //save the success
                                  newuser->setAuthenticated ( true );
                          }
                          else if ( newuser->isAuthenticated() ==true && olduser!=NULL )
                          {
                                  cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Don't add the user to the map, it is a rekeying.\n";
                          }
                         
                          if(newuser->getAuthControlFile().length()>0 && context->conf.getUseAuthControlFile())
                          {
                            write_auth_control_file(context, newuser->getAuthControlFile(), '1');
                          }
                          else
                          {
                            pthread_mutex_lock(context->getMutexRecv());
                            context->setResult(OPENVPN_PLUGIN_FUNC_SUCCESS);
                            pthread_cond_signal( context->getCondRecv( ));
                            pthread_mutex_unlock (context->getMutexRecv());
                          }
  
                  }
                  else //AUTH failed
                  {
                          if ( newuser->isAccounted()==true) //user is already known, delete him from the accounting
                          {
                                  cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Error ar rekeying!\n";
                                  //error on authenticate user at rekeying -> delete the user!
                                  //send the information to the background process
                                  context->acctsocketbackgr.send ( DEL_USER );
                                  context->acctsocketbackgr.send ( newuser->getKey() );
  
                                  //get the responce
                                  const int status = context->acctsocketbackgr.recvInt();
                                  if ( status == RESPONSE_SUCCEEDED )
                                  {
                                          if ( DEBUG ( context->getVerbosity() ) )
                                                  cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Accouting for user with key" << newuser->getKey()  << " stopped!\n";
                                  }
                                  else
                                  {
                                          cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Error in ACCT Background Process!\n";
                                          cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: User is deleted from the user map!\n";
                                  }
                          }
                          cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Error receiving auth confirmation from background process.\n";
                          //clean up: nas port, context, memory
                          context->delNasPort(newuser->getPortnumber());
                          context->delUser(newuser->getKey());

                          if(newuser->getAuthControlFile().length()>0 && context->conf.getUseAuthControlFile())
                          {
                            write_auth_control_file(context, newuser->getAuthControlFile(), '0');
                          }
                          else
                          {
                            pthread_mutex_lock(context->getMutexRecv());
                            context->setResult(OPENVPN_PLUGIN_FUNC_ERROR);
                            pthread_cond_signal( context->getCondRecv( ));
                            pthread_mutex_unlock (context->getMutexRecv());
                          }
                          delete newuser;
                  }
          }
          else
          {
              //clean up: nas port, context, memory
              context->delNasPort(newuser->getPortnumber());
              context->delUser (newuser->getKey());
              
              //return OPENVPN_PLUGIN_FUNC_ERROR;
              if(newuser->getAuthControlFile().length()>0 && context->conf.getUseAuthControlFile())
              {
                write_auth_control_file(context, newuser->getAuthControlFile(), '0');
              }
              else
              {
                pthread_mutex_lock(context->getMutexRecv());
                context->setResult(OPENVPN_PLUGIN_FUNC_ERROR);
                pthread_cond_signal( context->getCondRecv( ));
                pthread_mutex_unlock (context->getMutexRecv());
              }
              delete newuser;
          }
        }
        cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Thread finished.\n";
        pthread_exit(NULL);
}


/** Writes the result of the authentication to the auth control file (0: failure, 1: success).
 * @param filename The auth control file.
 * @param c The authentication result.
 */
void write_auth_control_file(PluginContext * context, string filename, char c)
{
  ofstream file;
  file.open(filename.c_str(),ios::out);
  if ( DEBUG ( context->getVerbosity() ))
    cerr << getTime() << "RADIUS-PLUGIN: Write " << c << " to auth_control_file "<< filename << ".\n";
  if (file.is_open())
  {
    file << c;
    file.close();
  }
  else
  {
    cerr << getTime() << "RADIUS-PLUGIN: Could not open auth_control_file "<< filename << ".\n";
  }

}

/** Returns the current time:
 * @return The current time as a string.
 */
string getTime()
{
  time_t rawtime;
  struct tm * timeinfo;
  time ( &rawtime );
  timeinfo = localtime ( &rawtime );
  string t(ctime(&rawtime));
  t.replace(t.find("\n"),1," ");
  return t;
}
