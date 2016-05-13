*******************************************
Names: Ram Brundavanam & Abdulrahman Kurdi
Usernames: rambrun & akurdi
Assignment Title: Socket Programming (netcat_part)
******************************************

Description: Our program can be classified into 2 different parts. One part is the server, and the other is the client. The client has 2 options, whether to send a message directly in the command line, or to send a file. The client sends this message or file to the specified IP address and port number. On the other hand, the server waits for an incoming connection from a client at some IP address (default being localhost) and some port number. If everything is successful, the server writes the result to a specified file. Our program enables a client to send a message or a file using the TCP protocol to a running server. Our program uses HMAC for message authentication.


How to Run: To Run this program simply type 'make'. This will create a netcat_part executable file.
Then simply type './netcat_part' to run the program.

Details: This program has multiple options that can be specified in the command line.
-h displays the helps screen which will show you a detailed description of every option and the specified argument order. The argument order is:

./netcat_part [OPTIONS] [dest_ip] [file_name]

Server example:
 ./netcat_part -v -l -p 8214 127.0.0.1 result.txt
 Client example:
 ./netcat_part -v -m "Howdy there Server!" -p 8214 127.0.0.1
 OR 
 ./netcat_part -v -p 8214 127.0.0.1 howdy_there.txt

-v displays the verbose output. This includes the IP address and the port number that you connected to. This works on both server and client.

-m "MSG" sends the message "MSG". This works only on client. We accomplished this by creating a socket, and connecting to the designated IP address. After the connection is established, we sent the message. File cannot be specified when sending a message. 

-p port This simply specifies the port number so that the user may change the port number if he or she so desires. By default, the port number is 6767 on both client and server.

-n bytes This specifies the number of bytes to send from the file. We used fseek() and rewind() to accomplish this task.

-o offset This specifies the number of bytes to offset into the file(the starting point to read from). We used fseek() and rewind() to accomplish this task. 

-l This option specifies that the server will be running. The server creates a temporary handshake socket and listens for a connection, once it gets the connection it establishes the new socket and accepts this new connection. It will then read from the socket automatically. 

Other notes/Assumptions: -l and -m "MSG" cannot be specified together. They represent 2 different 'modes'. By default, if neither -l and -m "MSG" are specified, then it is expected that the client will be attempting to send a file. The client sending a file uses the same rationale as the client sending a message.

Security: We used HMAC security. We specified a very weak made-up key called "abdulandram" (It's actually a very strong key, haha). This key is shared 'privately' with both the server and the client. We first, on the client side, calculate the digest from the hash function. We then append the length of the digest, with the digest, with the message. We send this combined message to the server. The server then uses the length of the digest to get the digest, and the message seperated. After doing so, the server uses the message and calculates its own digest using its own hash function. Then, it compares its digest with the digest it received from the server. If, and only if, the digests are the same, does the server then write the message onto the file specified. 




