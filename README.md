#PORTSCAN

##Overview

This script will scan for a given port or a port-range on a single host.

##Usage

	-t, --target [TARGET IP or HOSTNAME]
	The target host you want to scan

	-p, --port [PORTNUMBER]
	The port(s) or Portrange you want to scan. E.g. 80 or 80,443 or 80-100

	-l, --logging [TRUE or FALSE]
    Enables or disables logging. Default is False. Logging will create a CSV-File in the script dir.

	-h, --help
    Shows a quick help-message

##Example

Scanning for HTTP or HTTPS on the server example.org

	$ ./portscan.py -t www.example.org -p 80,443

Output:

	** CHECKING www.example.org	PORT: 80,443 **

	PORT	STATUS	FUNCTION
	----	------	--------
	80		OPEN	HTTP
	443		OPEN	HTTPS

Scanning for the first 5 Ports on 192.168.0.1

	$ ./portscan.py -t www.example.org -p 1-5

Scanning for SSH port on 192.168.0.1

	$ ./portscan.py -t www.example.org -p 22

##Contact

You can contact me via mail: [christoph.franke@me.com](christoph.franke@me.com).
