<?
	function auth_pop3_ssl($username, $password, $popserver)
	{
		/*
		Usage: auth_pop3_ssl('username', 'password', 'pop3.example.com')
		
		If the host is using SSL, prepend $popserver with "ssl://"
		
		Original code from:
		http://www.php.happycodings.com/E-Mail/code18.html
		
		Modified by Lord Matt:
		http://lordmatt.co.uk/item/1162/
		Updates and fixes by Andrew Peng:
		http://andrewpeng.net/computing/php-scripting/pop3-authentication
		
		This program is free software: you can redistribute it and/or modify
		it under the terms of the GNU General Public License as published by
		the Free Software Foundation, either version 3 of the License, or
		(at your option) any later version.
		
		This program is distributed in the hope that it will be useful,
		but WITHOUT ANY WARRANTY; without even the implied warranty of
		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
		GNU General Public License for more details.
		
		You should have received a copy of the GNU General Public License
		along with this program. If not, see http://www.gnu.org/licenses/.
		*/
		
		$isSSL = 0;
		
		if(substr($popserver, 0, 6) == "ssl://")
		{
			$isSSL = 1;
		}
		
		if(trim($username)=='')
		{
			return false;
		}
		
		else
		{
			if($isSSL)
			{	
				$fp = fsockopen("$popserver", 995, &$errno, &$errstr);
			}
	
			else
			{
				$fp = fsockopen("$popserver", 110, &$errno, &$errstr);
			}
	
			if(!$fp)
			{
				// failed to open POP3
				return false;
			}
	
			else
			{
				set_socket_blocking($fp,-1); // Turn off blocking
		
				/*
				Clear the POP server's Banner Text.
				eg.. '+OK Welcome to etc etc'
				*/
	
				$trash = fgets($fp,128); // Trash to hold the banner
				fwrite($fp,"USER $username\r\n"); // POP3 USER CMD
				$user = fgets($fp,128);
				$user = ereg_replace("\n","",$user);
	
				if ( ereg ("^\+OK(.+)", $user ) )
				{
					fwrite($fp,"PASS $password\r\n"); // POP3 PASS CMD
					$pass = fgets($fp,128);
					$pass = ereg_replace("\n","",$pass);
	
					if ( ereg ("^\+OK(.+)", $pass ) )
					{
						// User has successfully authenticated
						$auth = true;
					}
	
					else
					{
						// bad password
						$auth = false;
					}
				}
	
				else
				{
					// bad username
					$auth = false;
				}
	
				fwrite($fp,"QUIT\r\n");
				fclose($fp);
				return $auth;
			}
		}
	}
?>
