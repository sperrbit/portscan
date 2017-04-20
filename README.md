# PORTSCAN

## Overview

This script will scan for a given port or a port-range on a single host.

## Usage

	-t, --target [TARGET IP or HOSTNAME]
	The target host you want to scan

	-p, --port [PORTNUMBER]
	The port(s) or Portrange you want to scan. E.g. 80 or 80,443 or 80-100

	-h, --help
    Shows a quick help-message

## Example

Scanning for HTTP or HTTPS on the server example.org

	$ ./portscan.py -t www.example.org -p 80,443

Output:

	** Checking www.example.orbg **

	PORT	STATUS
	----	------
	80	OPEN
	443	OPEN

Scanning for the first 5 Ports on 192.168.0.1

	$ ./portscan.py -t www.example.org -p 1-5

Scanning for SSH port on 192.168.0.1

	$ ./portscan.py -t www.example.org -p 22

## Contact

You can contact me via mail: [mail@sysadmin-log.de](mail@sysadmin-log.de).
