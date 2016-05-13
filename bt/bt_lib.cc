/***************************************************************
Authors: Ram Brundavanam & Abdulrahman Kurdi
Class: CSCI-P538 - Computer Networks
Professor: Dr. Apu Kapadia
File: bt_lib.cc
Project: BitTorrent Client 
Date Due: October 17th 2014 11:00 pm
****************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <sys/stat.h>
#include <arpa/inet.h>

#include <openssl/sha.h> //hashing pieces

#include "bt_lib.h"
#include "bt_setup.h"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <regex.h>
#include <cmath>
using namespace std;

//predefine const values to be easily changed if needed
const int MAX_NUMBER_OF_MATCHES = 30; //Max number of regular expression matches

/*
This function takes in arguments structure and reads the torrent file

This function returns the torrent file in a character buffer
*/
char * read_torrent_file(bt_args_t bt_args){
  char * filepointer;
  FILE * torrentFile;
  // File Opening
  size_t filesize=sizeof(bt_args.torrent_file);
  torrentFile=fopen(bt_args.torrent_file,"r");

  //File sizing and reading
  if(torrentFile!=NULL){
    fseek(torrentFile,0,SEEK_END);
    filesize=ftell(torrentFile);
    rewind(torrentFile);
    filepointer=(char *)malloc(sizeof(char)* filesize);
    fread(filepointer, filesize, 1, torrentFile);
    fclose(torrentFile);
    return filepointer;
  }
  else{
    cout<<"The file was not opened succesfully"<<endl;
  }
}
 /*
This function takes in arguments structure and reads the torrent file

This function returns the torrent file in a character buffer
*/
string read_data_file(bt_info_t input){
  char * filepointer;
  FILE * inputFile;
  // File Opening
  size_t filesize = input.length;
  inputFile=fopen(input.name,"r");

  //File sizing and reading
  if(inputFile!=NULL){
    fseek(inputFile,0,SEEK_END);
    filesize=ftell(inputFile);
    rewind(inputFile);
    filepointer=(char *)malloc(sizeof(char)* filesize);
    fread(filepointer, filesize, 1, inputFile);
    string block(filepointer, input.length);
    fclose(inputFile);
    return block;
  }
  else{
    cout<<"The File was not opened Successfully"<<endl;
  }
} 

/*
This function takes in arguments as torrent file and parses the torrent file

This function returns the torrent information structure
*/
bt_info_t parse_torrent(char * buffer){
  
  vector<string> All_Matches;
  bt_info_t torrent_info;
  string temp_buffer;
  regex_t rx;
  int rx_status;
  int num_of_matches= 0;
  int n_matches = MAX_NUMBER_OF_MATCHES;
  regmatch_t pmatch[n_matches];
  char * prev_buffer = buffer;

  //Compile regular expression
  rx_status = regcomp(&rx,"([idel])|([0-9]+):|(-?[0-9]+)", REG_EXTENDED|REG_NEWLINE);
  if(rx_status) cout<<"Failed to compile regular expression"<<endl;
  else{
    while(1){ //START REGULAR EXPRESSION SCANNING
      int i=0;
      rx_status = regexec(&rx, buffer, n_matches, pmatch, 0);
      if(rx_status){
       //This means that no more matches were found
        break;
      }
      for(int i=0;i<n_matches;i++){
        int start_offset;
        int end_offset;
        string string_length;
        string bencode_string;

        if(pmatch[i].rm_so == -1) break;
        start_offset = pmatch[i].rm_so + (buffer - prev_buffer);
        end_offset = pmatch[i].rm_eo +  (buffer - prev_buffer);

        //Checking for String mode, aka digit:string
        if(isdigit(prev_buffer[i+start_offset]) && prev_buffer[i+end_offset-1] == ':') {
           for(int k=(i+start_offset); k<(i+end_offset-1);k++){
            //cocatenate digits onto string_length
              string_length += prev_buffer[k];
            }
            int str_leng = atoi(string_length.data());
            for(int j=end_offset; j< end_offset+str_leng; j++){
              bencode_string += prev_buffer[j];
            }
            All_Matches.push_back(bencode_string);
            pmatch[0].rm_eo += str_leng;
        }
         //Check for Integer mode, iDIGITSe
        else if(prev_buffer[i+start_offset] == 'i'){
             string bencode_int;
             int bencode_integer;
             int num_of_integers = 0;
             int current_loc = i+start_offset+1;
             while(prev_buffer[current_loc] != 'e'){
                if(isdigit(prev_buffer[current_loc])){
                  bencode_int += prev_buffer[current_loc];
                  current_loc++;
                  num_of_integers++;
                }
                else break;
             }
             bencode_integer = atoi(bencode_int.data());
             All_Matches.push_back(bencode_int);
             pmatch[0].rm_eo += num_of_integers;
        }
      }
      buffer += pmatch[0].rm_eo;
    }
    //Retrieve the bencoded values after parsing
    for(int h=0; h<All_Matches.size(); h++){
      if(All_Matches[h] == "name"){
        copy(All_Matches[h+1].begin(), All_Matches[h+1].end(), torrent_info.name);
        torrent_info.name[All_Matches[h+1].size()] = '\0';
      }
      else if(All_Matches[h] == "length"){
        torrent_info.length = atoi(All_Matches[h+1].data());
      }
      else if(All_Matches[h] == "piece length"){
        torrent_info.piece_length = atoi(All_Matches[h+1].data());
      } 
      else if(All_Matches[h] == "pieces"){ 
        torrent_info.num_pieces=All_Matches[h+1].length()/ID_SIZE; 
        cout<<"num of pieces"<<All_Matches[h+1].length()/ID_SIZE<<endl; 
        torrent_info.piece_hashes = new char *[torrent_info.num_pieces];
        const char * temp=All_Matches[h+1].data();
        int r, s;
        for(r=0;r<torrent_info.num_pieces;r++){ 
          torrent_info.piece_hashes[r]=new char [ID_SIZE];
          for(s=0;s<ID_SIZE;s++){ 
            torrent_info.piece_hashes[r][s]=temp[s];          
          } 
          temp+=ID_SIZE;  
        } 
      } 
    } 
    return torrent_info;
  }
  regfree(&rx);
  delete[] prev_buffer;
}

/*
This function takes in arguments a peer structure and reads initizes the sockets for the leechers

and returns the sockets 
*/
int initial_socket_cli_leecher(peer_t * peer){
  struct sockaddr_in server_addr; //contains information about the destination address
  struct hostent *server; // contains the address of the destination
  int client_socket, connection, sent_flag; //flags for creating socket, connecting, and sending

  //Creating a socket on client side
  client_socket = socket(AF_INET, SOCK_STREAM,0);
  if(client_socket < 0) cout<<"Failed to create socket!"<<endl;

  //Zeroing out the struct and assigning its port, address. It uses IPV4
  memset((char *)&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(peer->sockaddr.sin_port);
  cout<<"Server Address is: "<<inet_ntoa(peer->sockaddr.sin_addr)<<endl;
  server = gethostbyname(inet_ntoa(peer->sockaddr.sin_addr));
  memcpy((char *)&server_addr.sin_addr.s_addr,(char *)server->h_addr, server->h_length);
  //Connecting to server
  connection = connect(client_socket,(struct sockaddr *) &server_addr, sizeof(server_addr));
  if(connection < 0){ 
    cout<<"Server not found. Connection failed!"<<endl;
  }
  else{
    //If connection successful, then return the socket
    return client_socket;
  }
}

/*
This function takes in arguments a peer structure and reads initializes the sockets for the seeders

and returns the sockets 
*/
int initial_socket_ser_seeder(peer_t *peer){  
        struct sockaddr_in ser_addr, cli_addr;
        struct hostent *client;
        socklen_t cli_addr_len;
        //Various flags for checking the status
        int initial_socket, new_socket, bind_status;
        int listen_status, read_status;
        //Creating the handshake socket, and assigning values of IP address
        initial_socket = socket(AF_INET, SOCK_STREAM,0);
        if(initial_socket < 0) cout<<"Creating socket failed"<<endl;
        memset(&ser_addr, 0, sizeof(ser_addr));
        ser_addr.sin_family = AF_INET;
        ser_addr.sin_port = htons(peer->sockaddr.sin_port);
        client = gethostbyname(inet_ntoa(peer->sockaddr.sin_addr));
        memcpy((char *)&ser_addr.sin_addr.s_addr,(char *)client->h_addr, client->h_length);
        //Bind the socket, listen for a connection, and accept the connection at a new socket
        bind_status = bind(initial_socket, (struct sockaddr*) &ser_addr, sizeof(ser_addr));
        if(bind_status < 0){
          cout<<"Binding to the port failed, Please try another Port."<<endl; 
          exit(1);
        }
        listen_status = listen(initial_socket,5);
        if(listen_status < 0) cout<<"Listen failed"<<endl;
        cli_addr_len = sizeof(cli_addr);
        new_socket = accept(initial_socket,(struct sockaddr *) &cli_addr, &cli_addr_len);
        if(new_socket < 0) cout<<"Failed to accept Connection"<<endl;
        else return new_socket;

}

/*
This function takes in arguments structure and reads intitalizes the leecher socket
and returns individual sockets*/
vector<int> initialize_client_sockets(bt_args_t bt_args){
  vector<int> client_sockets;
  for(int i =0; i< MAX_CONNECTIONS; i++){
    if(bt_args.peers[i] != NULL && bt_args.peers[i]->type == 0){ 
       client_sockets.push_back(initial_socket_cli_leecher(bt_args.peers[i]));
    }
  }
  return client_sockets;  
}

/*
This function takes in arguments structure and reads intitalizes the leecher socket
and returns sockets
*/
vector<int> initialize_server_sockets(bt_args_t bt_args){
  vector<int> server_sockets;
  for(int i =0; i< MAX_CONNECTIONS; i++){
    if(bt_args.peers[i] != NULL && bt_args.peers[i]->type == 1) 
      server_sockets.push_back(initial_socket_ser_seeder(bt_args.peers[i]));
  }
  return server_sockets;  
}

/*
This function takes in arguments structure and length and reads on a particular seeder socket

This function returns the string that was read
*/
string server_read(bt_args_t bt_args, int i, int length){
  char Client_Msg[68] = {0};
  string s;
    if(bt_args.peers[i]->type == 1){
      
      int read_status=read(bt_args.sockets[i],Client_Msg,length);
      
      if(read_status < 0){
        cout<<"Unable to read from the socket"<<endl;
      }
        s = Client_Msg;
        return s;
    }
}

/*
This function takes in arguments structure and writes to a particular seeder socket the message specified
*/
void server_write(bt_args_t bt_args, int i, string message){
    if(bt_args.peers[i]->type == 1){
       int write_status = write(bt_args.sockets[i],message.data(), message.length());
       if(write_status < 0){
          cout<<"Unable to write"<<endl;
            }
    }
}

/*
This function takes in arguments structure and length and reads on a particular client socket

This function returns the string that was read
*/
string client_read(bt_args_t bt_args, int i, int length){
  char Server_Msg[68] = {0};
  string c;
    if(bt_args.peers[i]->type == 0){
      int read_status=read(bt_args.sockets[i],Server_Msg,length);
      if(read_status < 0){
        cout<<"Unable to read"<<endl;
      }
      c=Server_Msg;
      return c;   
    }
}

/*
This function takes in arguments structure and writes to a particular leecher socket the message specified
*/
void client_write(bt_args_t bt_args, int i, string message){
    if(bt_args.peers[i]->type == 0){
       int write_status = write(bt_args.sockets[i], message.data(), message.length());
       if(write_status < 0){
          cout<<"Unable to write"<<endl;
            }
    }
}

/*
This function takes in a socket and length of the message to read and reads on the socket

This function returns the string that was read
*/
string peer_read(int my_socket, int length){
  char Server_Msg[68] = {0};
  string c;
      int read_status=read(my_socket,Server_Msg,length);
      if(read_status < 0){
        cout<<"Unable to read"<<endl;
      }
      c = Server_Msg;
      return c;   
}

/*
This function takes in a socket and writes to that socket the message specified
*/
void peer_write(int my_socket, string message){
   int write_status = write(my_socket, message.data(), message.length());
   if(write_status < 0){
      cout<<"Unable to write"<<endl;
    }     
}
/*
This function takes in arguments structure and the hash and creates the handshake message

This function returns the handshake message
*/
string create_handshake_message(bt_args_t bt_args, int i, char hash[]){
  char bit = (unsigned char) 19;
  string infohash = hash;
  char ID[ID_SIZE];
  strncpy(ID, bt_args.peers[i]->id, ID_SIZE);
  string peer_ID = ID;
  string bit_message = " BitTorrent Protocol00000000";
  bit_message[0] = bit;
  bit_message.append(infohash);
  bit_message.append(peer_ID);
  cout<<"Message to send: "<<bit_message<<endl;
  return bit_message;
}

/*
This function takes in arguments structure and the message structure and creates the bitfield message

This function returns the bitfield message in a character buffer
*/
char * create_bitfield_message(bt_msg_t *my_message,bt_info_t torrent_info,bt_args_t bt_args,int i){
  my_message->payload.bitfield.bitfield= new char[torrent_info.num_pieces+1];
  int k;
  if(bt_args.peers[i]->type == 0)
    {
  
      for(k=0;k<torrent_info.num_pieces;k++)
      {
  
        my_message->payload.bitfield.bitfield[k]='0';
      }
    }
  else if(bt_args.peers[i]->type == 1)
    {
  
      for(k=0;k<torrent_info.num_pieces;k++)
      {
  
        my_message->payload.bitfield.bitfield[k]='1';
      }
    }
  my_message->payload.bitfield.bitfield[k]='\0';
  my_message->bt_type=5;
  my_message->payload.bitfield.size=strlen(my_message->payload.bitfield.bitfield);
  my_message->length = my_message->payload.bitfield.size + 1;
  return my_message->payload.bitfield.bitfield;
}

/*
This function takes in bitfield message and parses it

This function returns the parsed bitfield message
*/
string parse_bitfield(string raw_bitfield, int length){
  string len=static_cast<ostringstream*>( &(ostringstream()<< length) )->str();
  int index = raw_bitfield.find(len);
  string p_bitfield = raw_bitfield.substr(index+2);
  return p_bitfield;
}

/*
This function takes in arguments structure and creates a interested message

This function returns the interested message
*/
string client_generate_interested(bt_args_t *bt_args, bt_msg_t *my_message, int i){
  bt_args->peers[i]->interested = 1;
  my_message->length = 1;
  my_message->bt_type = 2;
  string len=static_cast<ostringstream*>( &(ostringstream()<< my_message->length) )->str();
  string type=static_cast<ostringstream*>( &(ostringstream()<< my_message->bt_type) )->str();
  string is_int_msg = len;
  is_int_msg.append(type);
  return is_int_msg;
}

/*
This function takes in the bitfield and determines what pieces the leecher wants
This function returns wanted piece indexes
*/
vector<int> pieces_wanted(string server_bitfield, string client_bitfield){
  char zero = '0';
  vector<int> indexes;
  for(int i=0; i<client_bitfield.size(); i++){
    if(client_bitfield[i] == zero) indexes.push_back(i);
  }
  return indexes;
}

/*
This function takes in torrent info structure and calculates the number of blocks needed

This function returns the number of blocks needed
*/
int calculate_number_of_blocks(bt_info_t t){
  if(t.length >= t.piece_length) return ceil((double) t.piece_length/32768.0);
  else if(t.length < t.piece_length) return ceil((double) t.length/32768.0);
}

/*
This function takes in torrent info structure and calculates the number of pieces needed

This function returns the number of pieces needed
*/
int calculate_number_of_pieces(bt_info_t t){
 return ceil((double)t.length/(double)t.piece_length);
}

/*
This function takes in request message and parses it on index

This function returns the index of the parsed message
*/
string parse_req_index(string message){
    string len=static_cast<ostringstream*>( &(ostringstream()<< 136) )->str();
    string req_index;
    int index=message.find(len);
    req_index = message.substr(index+3,1);
    return req_index;
}

/*
This function takes in request message and parses it on offset

This function returns the offset of the parsed message
*/
string parse_req_begin(string message){
  string req_begin;
    string len=static_cast<ostringstream*>( &(ostringstream()<< 136) )->str();
    int index=message.find(len);
     if(atoi(message.substr(index+4,1).c_str()) == 0){
       return req_begin = message.substr(index+4,1);
     }
     else if(atoi(message.substr(index+4,1).c_str()) == 1 || atoi(message.substr(index+4,1).c_str()) == 2){
       return req_begin = message.substr(index+4,6);
     }
     else{
      return req_begin = message.substr(index+4,5);
     }
}

/*
This function takes in request message and parses it on length

This function returns the length of the parsed message
*/
string parse_req_length(string message){
  string req_begin;
    string len=static_cast<ostringstream*>( &(ostringstream()<< 136) )->str();
    int index=message.find(len);
     if(atoi(message.substr(index+4,1).c_str()) == 0){
       return req_begin = message.substr(index+5,5);
     }
     else if(atoi(message.substr(index+4,1).c_str()) == 1 || atoi(message.substr(index+4,1).c_str()) == 2){
       return req_begin = message.substr(index+10,5);
     }
     else{
      return req_begin = message.substr(index+9,5);
     }
}

/*
This function takes in arguments and message structure and creates a request message

This function returns this request message
*/
string generate_request_message(bt_args_t *bt_args, bt_msg_t *my_message, int index, int block_index){
  string request_msg;
  my_message->length = 13;
  string thirteen=static_cast<ostringstream*>( &(ostringstream()<< my_message->length) )->str();
  request_msg = thirteen;
  my_message->bt_type = 6;
  string six=static_cast<ostringstream*>( &(ostringstream()<< my_message->bt_type) )->str();
  request_msg.append(six);
  string req_index=static_cast<ostringstream*>( &(ostringstream()<< index) )->str();
  request_msg.append(req_index);
  my_message->payload.request.index = index; //which piece to read from
  if(index == (bt_args->bt_info->num_pieces -1) && block_index == (bt_args->bt_info->num_blocks -1)){
    my_message->payload.request.length = bt_args->bt_info->piece_length % 32768;
  }
  else my_message->payload.request.length = 32768; //2^15, how much to read in bytes
  my_message->payload.request.begin += 32768; //where to start from reading
  string req_length=static_cast<ostringstream*>( &(ostringstream()<< my_message->payload.request.length) )->str();
  string req_offset=static_cast<ostringstream*>( &(ostringstream()<< my_message->payload.request.begin) )->str();
  request_msg.append(req_offset);
  request_msg.append(req_length);
  return request_msg;
}

/*
This function takes in arguments and message structure and creates a piece message

This function returns this piece message
*/
string generate_piece_message(bt_args_t *bt_args, bt_msg_t *my_message, int index, int begin, int length, string data_file){
  int len = 32777;
  int sev = 7;
  my_message->length = len;
  my_message->bt_type = sev;
  string leng=static_cast<ostringstream*>( &(ostringstream()<< len) )->str();
  string seven=static_cast<ostringstream*>( &(ostringstream()<< sev) )->str();
  string piece_msg = leng;
  piece_msg.append(seven);
  my_message->payload.piece.index = index;
  my_message->payload.piece.begin = begin;
  string ind=static_cast<ostringstream*>( &(ostringstream()<< index) )->str();
  string beg=static_cast<ostringstream*>( &(ostringstream()<< begin) )->str();
  piece_msg.append(ind);
  piece_msg.append(beg);
  string piece=data_file.substr((index)*(bt_args->bt_info->piece_length),bt_args->bt_info->piece_length);
  string block=piece.substr(begin,length);
  piece_msg.append(block);
  return piece_msg;
}

/*
This function takes in arguments structure and reads the torrent file

This function returns the torrent file in a character buffer
*/
void calc_id(char * ip, unsigned short port, char *id){
  char data[256];
  int len;
  
  //format print
  len = snprintf(data,256,"%s%u",ip,port);

  //id is just the SHA1 of the ip and port string
  SHA1((unsigned char *) data, len, (unsigned char *) id); 

  return;
}


/**
 * init_peer(peer_t * peer, int id, char * ip, unsigned short port) -> int
 *
 *
 * initialize the peer_t structure peer with an id, ip address, and a
 * port. Further, it will set up the sockaddr such that a socket
 * connection can be more easily established.
 *
 * Return: 0 on success, negative values on failure. Will exit on bad
 * ip address.
 *   
 **/
int init_peer(peer_t *peer, char * id, char * ip, unsigned short port, int type){
    
  struct hostent * hostinfo;
  //set the host id and port for referece
  memcpy(peer->id, id, ID_SIZE);
  peer->port = port;
  peer->type = type;  
  //get the host by name
  if((hostinfo = gethostbyname(ip)) ==  NULL){
    perror("gethostbyname failure, no such host?");
    herror("gethostbyname");
    exit(1);
  }
  
  //zero out the sock address
  bzero(&(peer->sockaddr), sizeof(peer->sockaddr));
      
  //set the family to AF_INET, i.e., Iternet Addressing
  peer->sockaddr.sin_family = AF_INET;
    
  //copy the address to the right place
  bcopy((char *) (hostinfo->h_addr), 
        (char *) &(peer->sockaddr.sin_addr.s_addr),
        hostinfo->h_length);
    
  //encode the port
  peer->sockaddr.sin_port = htons(port);
  
  return 0;

}

/**
 * print_peer(peer_t *peer) -> void
 *
 * print out debug info of a peer
 *
 **/
void print_peer(peer_t *peer){
  int i;

  if(peer){
    printf("peer: %s:%u ",
           inet_ntoa(peer->sockaddr.sin_addr),
           peer->port);
    printf("id: ");
    for(i=0;i<ID_SIZE;i++){
      printf("%02x",peer->id[i]);
    }
    printf("\n");
  }
}



