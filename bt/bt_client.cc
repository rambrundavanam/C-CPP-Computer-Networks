/***************************************************************
Authors: Ram Brundavanam & Abdulrahman Kurdi
Class: CSCI-P538 - Computer Networks
Professor: Dr. Apu Kapadia
File: bt_client.cc
Project: BitTorrent Client 
Date Due: October 17th 2014 11:00 pm
****************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h> //ip hdeader library (must come before ip_icmp.h)
#include <netinet/ip_icmp.h> //icmp header
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <regex.h>
#include <cmath>
#include <sstream>
#include <time.h>
#include "bt_lib.h"
#include "bt_setup.h"
#include "openssl/sha.h"
using namespace std;

int main (int argc, char * argv[]){

  //create arguments structure
  bt_args_t bt_args;
  int i;

  //used for random functionality
  srand (time(NULL));

  //parses arguments from the command line
  parse_args(&bt_args, argc, argv);

  //Prints some verbose output
  if(bt_args.verbose){
    printf("Args:\n");
    printf("verbose: %d\n",bt_args.verbose);
    printf("save_file: %s\n",bt_args.save_file);
    printf("log_file: %s\n",bt_args.log_file);
    printf("torrent_file: %s\n", bt_args.torrent_file);

    for(i=0;i<MAX_CONNECTIONS;i++){
      if(bt_args.peers[i] != NULL)
        print_peer(bt_args.peers[i]);
    }
    
  }

  //Read the torrent file
  string temp_buffer = read_torrent_file(bt_args);

  //Assigning the taken file string to buffer
  char * buffer = &temp_buffer[0];

  //Parse the torrent file
  bt_info_t torrent_info = parse_torrent(buffer);

  //Set the torrent info to the structure
  bt_args.bt_info = &torrent_info;

  //Read the input file
  string data_file = read_data_file(torrent_info);

  //Calculate the number of blocks for the file
  int NUM_OF_BLOCKS = calculate_number_of_blocks(torrent_info);

  //Print some verbose output, torrent file arguments
  if(bt_args.verbose){
    cout<<"***************************************"<<endl;
    cout<<"Torrent Details"<<endl;
    cout<<"------------------"<<endl;
    cout<<"Name:             "<<torrent_info.name<<endl;
    cout<<"Length:           "<<torrent_info.length<<endl;
    cout<<"Piece Length:     "<<torrent_info.piece_length<<endl;
    cout<<"Number of Pieces: "<<torrent_info.num_pieces<<endl;
    cout<<"***************************************"<<endl;
  }

  //Initialize all leecher sockets
  bt_args.sockets = initialize_client_sockets(bt_args);
  //Initialize all seeder sockets
  vector<int> serv_sockets = initialize_server_sockets(bt_args);
  //Join the sockets together for convenience
  bt_args.sockets.insert(bt_args.sockets.end(), serv_sockets.begin(), serv_sockets.end());

  //Calculate the SHA1 hash
  unsigned char hash[SHA_DIGEST_LENGTH];
  int index= temp_buffer.find("info");
  string info=temp_buffer.substr(index+5);
  info.erase(info.end()-1,info.end());
  SHA1((const unsigned char *)info.data(), info.size(), hash);

  //Initial Handshake. Comparing the full handshake between seeders and leechers
  string s_handshake, c_handshake;
  string temp12;
  bt_msg_t my_message;
  bool s_should_unchoke = false;
  bool c_should_unchoke = false;
  bool is_interested = false;
  string unchoke_message;

  for(int i =0; i< bt_args.sockets.size(); i++){
    if(bt_args.peers[i]->type == 1){ //Seeder type
      //Seeder creates the handshake message
      s_handshake = create_handshake_message(bt_args, i,(char *)hash);
      temp12 = server_read(bt_args,i,s_handshake.length());
      //Seeder compares the handshake messages
      if(s_handshake.compare(0,68,temp12,0,68) == 0){ 
        cout<<"Handshake successful"<<endl; 
      }
      else{ 
        cout<<"Handshake failed"<<endl;
      }
      //Seeder sends the handshake message
      server_write(bt_args, i, s_handshake);
      string unchoke_msg = "11";
      string temp22 = peer_read(bt_args.sockets[i], unchoke_msg.length());

      if(unchoke_msg.compare(temp22) == 0){
        cout<<"Setting to Unchoked Successful"<<endl;
        bt_args.peers[i]->choked = 1;
      }
      else{
        cout<<"Peer is choked!"<<endl;
      }
      //Seeder creates and writes the bitfield 
      string createserverbitfield= create_bitfield_message(&my_message,torrent_info,bt_args,i);
      string finalserverbitfield;
      string b=static_cast<ostringstream*>( &(ostringstream()<<my_message.payload.bitfield.size + 1) )->str();
      finalserverbitfield=b;
      cout<<finalserverbitfield<<endl;
      string a=static_cast<ostringstream*>( &(ostringstream()<< my_message.bt_type  ) )->str();
      finalserverbitfield.append(a);
      finalserverbitfield.append(createserverbitfield);
      cout<<"Bitfield message is"<<finalserverbitfield<<endl;
      server_write(bt_args,i, finalserverbitfield);
      //Seeder ends writing bitfield 
      //Seeder starts reading interested
      string inter_msg = "12";
      if(inter_msg.compare(peer_read(bt_args.sockets[i],inter_msg.length())) == 0){
        cout<<"Client is interested!"<<endl;
        is_interested = true;                 
      }
      //End seeder interested
      //Seeder recieves request messages on a per-block basis
      string req_msg;
      for(int s=0; s<torrent_info.num_pieces; s++){
        if(s == torrent_info.num_pieces -1){
          torrent_info.piece_length = torrent_info.length % torrent_info.piece_length;
          NUM_OF_BLOCKS = ceil((double)torrent_info.piece_length / 32768.0);
          torrent_info.num_blocks = NUM_OF_BLOCKS;
        }
        for(int k=0; k<NUM_OF_BLOCKS; k++){
          if(k == 0)req_msg = peer_read(bt_args.sockets[i],10);
          else if(k > 0 && k < 4) req_msg = peer_read(bt_args.sockets[i],14);
          else if(k > 3)req_msg = peer_read(bt_args.sockets[i],15);
          cout<<"Request Message: "<<req_msg<<endl;
          int req_index,req_begin,req_length;
          req_index = atoi(parse_req_index(req_msg).c_str());
          req_begin = atoi(parse_req_begin(req_msg).c_str());
          req_length = atoi(parse_req_length(req_msg).c_str());
          //At this point, Seeder has parsed the request message
          //Seeder creates piece messages and sends them block by block (sending is successful, receiving has problems)
          if(is_interested && bt_args.peers[i]->choked == 1){
            string pce_msg = generate_piece_message(&bt_args, &my_message,req_index,req_begin, req_length, data_file);
            //cout<<"Piece Message: "<<pce_msg<<endl;
            //peer_write(bt_args.sockets[i],pce_msg);
          }
        }
      }
    }

    else if(bt_args.peers[i]->type == 0){//Leecher type
      //Creating Leecher handshake, writing and comparing
      c_handshake = create_handshake_message(bt_args, i,(char *)hash);
      client_write(bt_args, i, c_handshake);
      if(c_handshake.compare(0,68,client_read(bt_args,i, c_handshake.length()),0,68) == 0){
        cout<<"Handshake successful"<<endl;

        //Prepare Choke message
        bt_args.peers[i]->choked = 1;//setting current peer to unchoked
        my_message.bt_type = 1; //setting BitTorrent Protocol message type to 1
        my_message.length = 1; //setting message length to 1
        string type_unchoke = static_cast<ostringstream*>( &(ostringstream() << my_message.bt_type) )->str();
        unchoke_message = static_cast<ostringstream*>( &(ostringstream() << my_message.length) )->str();
        unchoke_message.append(type_unchoke);
        s_should_unchoke = true;
       }
      else cout<<"Handshake failed"<<endl;
      //If the leecher is unchoked, send an unchoke message to the seeder to begin communication
      if(s_should_unchoke){
        peer_write(bt_args.sockets[i],unchoke_message);
        s_should_unchoke = false;
      }
      //Leecher creates its own and reads the bitfield message from Seeder
      string createclientbitfield= create_bitfield_message(&my_message,torrent_info,bt_args,i);
      cout<<"Bitfield message is: "<<createclientbitfield<<endl;
      string serversays=client_read(bt_args,i,my_message.length +2);
      string serv_bitfield = parse_bitfield(serversays, my_message.length);
      //Leecher ends bitfield section
      //Leecher compares the bitfield, and sends interested message
      if(serv_bitfield.compare(createclientbitfield) != 0){
        string int_message = client_generate_interested(&bt_args, &my_message, i);
        peer_write(bt_args.sockets[i], int_message);
      }
        //End leecher interested
      //Leecher determines what pieces it wants
      vector<int> int_index = pieces_wanted(serv_bitfield,createclientbitfield);
      int last_index = int_index[int_index.size()-1];
      int_index.pop_back();
      //Randomize the piece requests
      random_shuffle(int_index.begin(), int_index.end());
      int_index.push_back(last_index);
      my_message.payload.request.begin = -32768;
      string unparsed_pce_msg, parsed_block;

      //Leecher generates the request message for each block
      for(int z=0; z<torrent_info.num_pieces; z++){
        if(z == torrent_info.num_pieces -1){
          torrent_info.piece_length = torrent_info.length % torrent_info.piece_length;
          NUM_OF_BLOCKS = ceil((double)torrent_info.piece_length / 32768.0);
          torrent_info.num_blocks = NUM_OF_BLOCKS;
          my_message.payload.request.begin = -32768;
        }
        for(int g=0; g<NUM_OF_BLOCKS;g++){
          string req_msg = generate_request_message(&bt_args, &my_message, int_index[z], g);
          if(my_message.payload.request.begin == torrent_info.piece_length){
            my_message.payload.request.begin = -32768;
            g--;
          }
          else{
            //Leecher writes all request messages
            cout<<"Request message:"<<req_msg<<endl;
            peer_write(bt_args.sockets[i],req_msg);
          }
          // Problems reading the successfully written piece message blocks
          //Peer sent request, will do read the piece block from other peer
          // if(g == NUM_OF_BLOCKS - 1) unparsed_pce_msg = peer_read(bt_args.sockets[i], my_message.payload.request.length+13);
          // else if(g == 0) unparsed_pce_msg = peer_read(bt_args.sockets[i], 32776);
          // else if(g > 0 && g < 4) unparsed_pce_msg = peer_read(bt_args.sockets[i], 32780);
          // else if(g > 3 && g < NUM_OF_BLOCKS-1) unparsed_pce_msg = peer_read(bt_args.sockets[i], 32781);
        }
      }
    }
  }
  return 0;
}
