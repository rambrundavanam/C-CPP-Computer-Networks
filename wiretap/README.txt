--------------------------------------
README
Names: Abdulrahman Kurdi & Ram Brundavanam
Class: CSCI P-538 -- Computer Networks
Project name: WireTap
Professor: Dr. Apu Kapadia
Date Due: October 30th 2014 11:00 pm
-------------------------------------

------------------------------------
Project Description: The goal of this project is to parse a packet capture file (.pcap)
Given a pcap file, we display the different addresses, ports, protocols, sizes, types. etc.
in a nice readable and concise manner. We display this information in a hierarchical manner,
with the Link Layer information first, and the transport layer last (including TCP, UDP, ICMP details)
-------------------------------------

------------------------------------
Files: 
wiretap.cc 
	This contains our main, and all functions and structures used to complete this project.
Makefile
	This is the makefile. It compiles and links our code.
README.txt
	This file explains our program and how we went about implementing it
We also used various linux header files, and structures to avoid having "magic" numbers in our code
-------------------------------------

------------------------------------
Detailed description: 
The main design of our program is based on the callback function of the pcap_loop() function.
This function runs once for every single packet that is sniffed. It then saves all information 
into a structure that we created. After we have all the information we need (i.e after all packets
have been sniffed), we then analyze and parse out detailed information that we need from the 
information that was stored. It is also important to note that if the packet is corrupted, then the
callback function simply exits out, and moves on to the next packet.
------------------------------------

------------------------------------
How to Run the program:
	To display help options:
		./wiretap --help
	To parse out a pcap file called somefile.pcap:
		./wiretap --open somefile.pcap
------------------------------------


