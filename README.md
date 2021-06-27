# auth-pop3-ssl

This is a simple PHP script that will attempt to authorize via pop3 to check for credentials. This is forked form the below sources and modified to check for TLS / SSL connections. 

Usage: auth_pop3_ssl('username', 'password', 'pop3.example.com')

If the host is using SSL, prepend $popserver with "ssl://"

This script uses several external scripts and resources:
* Original code from: 
http://www.php.happycodings.com/E-Mail/code18.html
* Modified by Lord Matt: 
http://lordmatt.co.uk/item/1162/

***

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/.
