
/***************************************************************
Authors: Ram Brundavanam & Abdulrahman Kurdi
Class: CSCI-P538 - Computer Networks
Professor: Dr. Apu Kapadia
File: netcat_part.cc
Project: TCP Socket Program with HMAC Security (Socket Programming -netcat_part)
Date Due: September 17th 2014 11:00 pm
****************************************************************/

#include <iostream>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <netdb.h>
#include <stdio.h>
#include <openssl/hmac.h>

using namespace std;

/*
This function simply prints out the help screen to stdout.
*/
void print_help_screen(){
	cout<<"netcat_part [OPTIONS] dest_ip [file] "<<endl;
	cout<<"-h 							Print this help screen"<<endl;
	cout<<"-v 							Verbose output"<<endl;
	cout<<"-m 							Send the message specified on the command line."<<endl;
	cout<<"							Warning: if you specify this option, you do not specify a file."<<endl;
	cout<<"-p 							Set the port to connect on (dflt: 6767)"<<endl;
	cout<<"-n 							Number of bytes to send, defaults whole file"<<endl;
	cout<<"-o 							Offset into file to start sending"<<endl;
	cout<<"-l 							Listen on port instead of connecting and write output to file"<<endl;
	cout<<"							and dest_ip refers to which ip to bind to (dflt: localhost)"<<endl;
}

/*
This function takes in an error number based on the type of error that has occured.

This function prints out the error message and exits.
*/
void standard_error(int error_number){
	if(error_number == 1){
		cout<<"Invalid amount of arguments"<<endl;
		print_help_screen();
	}
	else if(error_number == 2) cout<<"Server not found. Connection failed!"<<endl;
	else if (error_number == 3) cout<<" Sending message failed!"<<endl;
	else if(error_number == 4) cout<<"Error opening file!"<<endl;
	else if(error_number == 5) cout<<"Failed to create socket!"<<endl;
	else if(error_number == 6) cout<<"Bind failed!"<<endl;
	else if(error_number == 7) cout<<"Listen failed!"<<endl;
	else if(error_number == 8) cout<<"Failed to accept connection"<<endl;
	else if(error_number == 9) cout<<"Read Failed!"<<endl;
	else if(error_number == 10) cout<<"Hashes do not match! Message has been changed."<<endl;
	else if(error_number == 11){
		cout<<"Invalid option choice. Enter -h for help."<<endl;
		print_help_screen();
	} 
	exit(1);
}

/*
This function takes in the message the client needs to send, the IP address of
the destination and the port at which the socket should be created. It then
creates the socket and attempts to connect to the server. It also takes in the hash,
and the its length. It will append the hash length, hash, and the message together.
It will then attempt to send that to the server. 

This function returns 1 if successful and -1 if not.
*/
int send_message(char * message, char * dest_addr, int port, char * hash, int hash_leng){

			struct sockaddr_in server_addr; //contains information about the destination address
			struct hostent *server; // contains the address of the destination
			int client_socket, connection, sent_flag; //flags for creating socket, connecting, and sending
			char * final_message = (char *)malloc( (strlen(hash)*2) + strlen(message) + 10);//contains the combined message-hash-hash_length. Allocates enough memory.
			
			//Convert the hash to hexadecimal
   		 	char new_hash[20]; 
   			for(int k = 0; k < 20; k++) sprintf(&new_hash[k*2], "%02x", (unsigned int)hash[k]);

			char temp[3];//contains the char value of hash length
			//Convert Hash length to char *
			snprintf(temp, sizeof(temp), "%d", hash_leng);
			//Add in hash_length first. then hash, then message
			strcpy(final_message, temp);
			strcat(final_message, new_hash);
			strcat(final_message, message);

			//Creating a socket on client side
			client_socket = socket(AF_INET, SOCK_STREAM,0);
			if(client_socket < 0) standard_error(5);

			//Zeroing out the struct and assigning its port, address. It uses IPV4
			memset((char *)&server_addr, 0, sizeof(server_addr));
			server_addr.sin_family = AF_INET;
			server_addr.sin_port = htons(port);
			server = gethostbyname(dest_addr);
			memcpy((char *)&server_addr.sin_addr.s_addr,(char *)server->h_addr, server->h_length);

			//Connecting to server
			connection = connect(client_socket,(struct sockaddr *) &server_addr, sizeof(server_addr));
			if(connection < 0){ 
				standard_error(2);
				return -1;
			}
			else{
				//If connection successful, then write to the socket
				sent_flag = write(client_socket, final_message, strlen(final_message));
				if(sent_flag < 0) standard_error(3);
				else
					cout<<"Message sent successfully!"<<endl;
				return 1;
			}
}

int compare_hash_and_write(char * Client_Msg, int indent, char * key, char * file_name){

		//Seperate the hashlength from the rest of the message and convert to integer
		char hash_length[2] = {0};
		for(int n =0; n< 2; n++) hash_length[n] = Client_Msg[n];
		int h_leng = atoi(hash_length);

		//Seperate the hash from the message using the hash length
		h_leng = 2 + indent + (h_leng * 2) ;
		char Hash[h_leng];
		for(int m=2; m < h_leng; m++) Hash[m-2] = Client_Msg[m];

		//Seperate the message from the rest
		char Final_Message[strlen(Client_Msg)-h_leng];
		int temp_size = sizeof(Final_Message);

		for(int e=0; e < sizeof(Final_Message); e++) Final_Message[e] = 0;

		for(int r=h_leng; r < strlen(Client_Msg); r++){ 
			Final_Message[r-h_leng] = Client_Msg[r];
		}
		for(int g=temp_size; g<strlen(Final_Message); g++){
			Final_Message[g] = NULL;
		}

		//Generate server hash from the message
		unsigned char * arr3;
		char server_hash[20];
		unsigned int server_hash_leng;
		arr3 = HMAC(EVP_sha1(),key, strlen(key), (unsigned char *)Final_Message, strlen(Final_Message),(unsigned char *)server_hash, &server_hash_leng);

		//Convert server hash to hexadecimal
		bool MESSAGE_TAMPERED = false;
	   	char new_server_hash[20];
		for(int z = 0; z < 20; z++) sprintf(&new_server_hash[z*2], "%02x", (unsigned int)server_hash[z]);

		//Compare the 2 Hashes
		for(int y=0; y <(h_leng-6); y++){
			if(Hash[y] != new_server_hash[y]) MESSAGE_TAMPERED = true;
		}
		if(MESSAGE_TAMPERED) return -1;
		else{
			//If not tampered, write the message to the file specified
			FILE * Output_File;
			Output_File = fopen(file_name, "w+");
			fwrite(Final_Message ,1, sizeof(Final_Message), Output_File);
			fclose(Output_File);
		 	return 1;
		 }	
}

int main(int argc, char *argv[]){
	char* x; //pointer to OPTIONS
	char options; //contains the character of each option
	bool MSG_FROM_USER = false; //true when a client is sending a message
	bool SERVER_RUNNING = false; //true when the server is running
	bool VERBOSE_OUT = false; //if true, will send verbose output to stdout
	bool SENT_SOMETHING = false; //true when client sends a file or message
	bool Num_of_Bytes_Changed = false; //true when user specifies num of bytes to send
	bool Offset_Changed = false; //true when user specifies at what offset to send
	bool DEFAULT_ADDRESS = false; //true in server when user doesn't specify IP Address
	int connect_status = 0; // 1 = Client Sending success, -1 = Client Sending unsuccessful
	int port_no = 6767; //The default port_no is 6767. Used by Client and Server.
	int num_of_bytes =0; //The number of bytes to write into socket
	int offset = 0; //The offset at which to write into socket
	int current_i = 0; // Refers to the position of the message that client wants to send
	char key[] = "abdulandram"; //The key used in HMAC

	//If there's only one argument, it's an error
	if(argc < 2) standard_error(1);
	//Go through every single argument
	for(int i = 1; i < argc; i++){
		x = argv[i];
		//2 General cases: with a '-' or without. This is the latter.
		if(*x != '-'){
			//If no options were set, then client will send the designated file here
			if(!MSG_FROM_USER && !SERVER_RUNNING && !SENT_SOMETHING){
				//There must be at least an IP Address & file name, if not then error
				if(argc < 3) standard_error(1);
				//Open the file, get the file size, read the file,
				// Save into character array, send that to server
				char client_msg[256];
				FILE * client_file = fopen(argv[argc-1],"r");
				if(client_file == NULL) standard_error(4);
				else{
					//Getting the file size
					int file_size;
					fseek(client_file,0,SEEK_END);
					file_size = ftell(client_file);

					rewind(client_file);//Reset the pointer to the start of the file

					//Read from the file based on offset and num of bytes
					if(!Offset_Changed && !Num_of_Bytes_Changed)
					 fread(client_msg,1,file_size,client_file);
					else if(Offset_Changed || Num_of_Bytes_Changed){
						fseek(client_file, offset, SEEK_SET);
						fread(client_msg,1,num_of_bytes,client_file);
					}
					//Generate the hash for the file, and send the message+hash+hash_leng
					if (!SENT_SOMETHING && !SERVER_RUNNING){
						unsigned char * arr2;
						char client_file_hash[20];
						unsigned int client_file_hash_leng;
						arr2 = HMAC(EVP_sha1(),key, strlen(key), (unsigned char *)client_msg, strlen(client_msg),(unsigned char *)client_file_hash, &client_file_hash_leng);

						connect_status = send_message(client_msg,argv[argc-2], port_no, (char *) client_file_hash, client_file_hash_leng);
						if(connect_status > 0 && VERBOSE_OUT){
							cout<<"TCP Connection succeeded at IP: "<<argv[argc-2]<<" with Port: "<<port_no<<endl;
						}
						SENT_SOMETHING = true;
					}
					fclose(client_file);
				}
				
			}//END PART FOR CLIENT SENDING FILE
			//Client sending a message
			else if(MSG_FROM_USER){
				if(!SENT_SOMETHING && !SERVER_RUNNING){
					//Generate the hash for the message, and send the message+hash+hash_leng
					unsigned char * arr;
					char client_msg_hash[20];
					unsigned int client_msg_hash_leng;
					arr = HMAC(EVP_sha1(),key, strlen(key), (unsigned char *)argv[current_i], strlen(argv[current_i]),(unsigned char *)client_msg_hash, &client_msg_hash_leng);
					connect_status =send_message(argv[current_i], argv[i],port_no, (char *) client_msg_hash, client_msg_hash_leng);
					if(connect_status > 0 && VERBOSE_OUT){
						cout<<"TCP Connection succeeded at IP: "<<argv[argc-1]<<" with Port: "<<port_no<<endl;
						}
					SENT_SOMETHING = true;
				}
				MSG_FROM_USER = false;
			}
			//Server waiting for a connection
			else if(SERVER_RUNNING){
				char Client_Msg[28672];
				struct sockaddr_in ser_addr, cli_addr;
				struct hostent *client;
				socklen_t cli_addr_len;
				//Various flags for checking the status
				int initial_socket, new_socket, bind_status;
				int listen_status, read_status;

				//Clearing the client message buffer before reading into it
				memset(&Client_Msg[0], 0, sizeof(Client_Msg));

				//Creating the handshake socket, and assigning values of IP address
				initial_socket = socket(AF_INET, SOCK_STREAM,0);
				if(initial_socket < 0) standard_error(5);
				memset(&ser_addr, 0, sizeof(ser_addr));
				ser_addr.sin_family = AF_INET;
				ser_addr.sin_port = htons(port_no);
				
				if (!DEFAULT_ADDRESS) client = gethostbyname(argv[argc-2]);
				else{ 
					client = gethostbyname("localhost");
					i++;
				}
				memcpy((char *)&ser_addr.sin_addr.s_addr,(char *)client->h_addr, client->h_length);

				//Bind the socket, listen for a connection, and accept the connection at a new socket
				bind_status = bind(initial_socket, (struct sockaddr*) &ser_addr, sizeof(ser_addr));
				if(bind_status < 0) standard_error(6);
				listen_status = listen(initial_socket,5);
				if(listen_status < 0) standard_error(7);
				cli_addr_len = sizeof(cli_addr);
				new_socket = accept(initial_socket,(struct sockaddr *) &cli_addr, &cli_addr_len);
				if(new_socket < 0) standard_error(8);
				if(VERBOSE_OUT){
					if(!DEFAULT_ADDRESS)cout<<"TCP Connection accepted at IP: "<<argv[argc-2]<<" with Port: "<<port_no<<endl; //Need to fix this
					else cout<<"TCP Connection accepted at localhost with Port: "<<port_no<<endl;
				}

				//Read from the socket
				read_status = read(new_socket,Client_Msg,28671);
				if(read_status < 0) standard_error(9);

				//Create server hash, compare to hash received from the client
				int auth_1 = compare_hash_and_write(Client_Msg, 6, key, argv[argc-1]);
				int auth_2 = 0;
				if(auth_1 < 0) auth_2 = compare_hash_and_write(Client_Msg, 0, key, argv[argc-1]);
				if(auth_1 < 0 && auth_2 < 0) standard_error(10);
				else cout<<"Message Authentication successful"<<endl;

				SERVER_RUNNING = false;
				exit(0);
			}	
		}
		//Traverse through options, setting flags where needed 
		else{
			x++;
			options = *x;
			if(options == 'h'){
				if(argc > 2) standard_error(1);
				print_help_screen();
			}
			else if(options == 'v'){
				VERBOSE_OUT = true;
				if(i == (argc-2)) DEFAULT_ADDRESS = true;
			}
			else if(options == 'm'){
				MSG_FROM_USER = true;
				i++;
				current_i = i;
			}
			else if(options == 'l'){
				SERVER_RUNNING = true;
				if(i == (argc-2))DEFAULT_ADDRESS = true;	
			}
			else if(options == 'p'){
				port_no = atoi(argv[i+1]);
				i++;
				if( i == (argc-2)) DEFAULT_ADDRESS = true;
			}
			else if(options == 'n'){
				num_of_bytes = atoi(argv[i+1]);
				Num_of_Bytes_Changed = true;
				i++;
			}
			else if(options == 'o'){
				offset = atoi(argv[i+1]);
				Offset_Changed = true;
				i++;
			}
			else{
				standard_error(11);
			}
		}
	}//end of For loop
}
