--------------------------------------
README
Names: Abdulrahman Kurdi & Ram Brundavanam
Class: CSCI P-538 -- Computer Networks
Project name: Port Scanner
Professor: Dr. Apu Kapadia
Date Due: December 4th 2014 11:00 pm
-------------------------------------

------------------------------------
Project Description: The goal of this project is to scan the ports on different IP addresses and determine conclusions based on the different results.
Given a IP address and port, we scan the port specified on the specified IP and display the results in a nice readable and concise manner.

Port scanner is basically an imitation of the popular NMAP scanner.
-------------------------------------

------------------------------------
Files: 

portScanner.cc 
This contains our main

ps_lib.cc 
This contains most functions and structures used to complete this project.

ps_lib.h
This is the library file which contains the different functions we used and structures we defined in the code

ps_parse.h
This file contains the ps arguments structure that we basically implemented for the command line. These values are set on the command line.
We also have different parsing functions that are used in the project

ps_parse.cc
This file contains the parse arguments function where we parse the command line arguments.
	
Makefile
This is the makefile. It compiles and links our code.

TCPPorts
This file contains the list of port names we mapped to the  port numbers specified

README.txt
This file explains our program and how we went about implementing it
We also used various linux header files, and structures to avoid having "magic" numbers in our code
-------------------------------------------------------------------------


Detailed description: 
------------------------------------
We used pcap to sniff packets. We used raw sockets to create and send packets. We create our own IP headers. We parse the packets and determine conclusions. Our conclusions are determined with SYN being the most reliable, then UDP, then ACK, then the NULL, XMAS, and FIN scans.  
------------------------------------
How to Run the program:
	To display help options:
		./portScanner --help
	To parse out a text file with a list of IP addresses:
		./portScanner --ip (address)/ --file (filename) --ports (number or Range or combination) --scan (scan types) --speed (number of threads)
------------------------------------



