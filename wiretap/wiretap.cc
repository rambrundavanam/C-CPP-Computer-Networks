/***************************************************************
Authors: Ram Brundavanam & Abdulrahman Kurdi
Class: CSCI-P538 - Computer Networks
Professor: Dr. Apu Kapadia
File: wiretap.cc
Project: Wiretap
Date Due: October 30th 2014 11:00 pm
****************************************************************/
#include <netinet/in.h>
#include <netinet/ip.h> //ip hdeader library (must come before ip_icmp.h)
#include <netinet/ip_icmp.h> //icmp header
#include <netinet/ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <pcap/pcap.h>
#include <pcap/bpf.h>
#include <linux/if_ether.h>
#include <iostream>
#include <algorithm>
#include <string>
#include <sstream>
#include <vector>
#include <cstdlib>


#define NEGATIVE_VALUE -1 //This tells pcap_loop to run until it gets an error (i.e. sniff all packets)
#define MAX_PROTO_TYPE 16 

using namespace std;

// ARP Header
struct arphdr_t{ 
    u_int16_t htype;       //Hardware Type            
    u_int16_t ptype;       //Protocol Type            
    u_char hlen;           //Hardware Address Length  
    u_char plen;           //Protocol Address Length  
    u_int16_t oper;        //Operation Code           
    u_char sha[ETH_ALEN];  //Sender hardware address 
    u_char sip[4];         //Sender IP address        
    u_char tha[ETH_ALEN];  //Destination hardware address  
    u_char tip[4];         //Destination IP address   
}; 

//This packets structure contains all information about every packet
typedef struct{
  //contains the time values from packet header
  vector<timeval> times;
  //contains the sizes of the packets from packet header
  vector<int> sizes;

  //contains the ethernet MAC source addresses
  vector<string> eth_sources;
  //contains the ethernet MAC destination addresses
  vector<string> eth_dests;
  //contains the network layer protocol types
  vector<int> eth_types;

  //contains the IP source addresses 
  vector<string> ip_src_address;
  //contains the IP destination addresses
  vector<string> ip_dest_address;
  //contains the IP Time-to-live values
  vector<string> ip_TTL;
  //contains the transport layer protocol types
  vector<int> ip_type;
  //contains the MAC and IP addresses(source) of ARP packets
  vector<string> arp_addr;

  //contains all the TCP source ports
  vector<string> tcp_sources;
  //contains all the TCP destination ports
  vector<string> tcp_dests;

  //flags for TCP
  int urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag;

  //contains all TCP options found
  vector<int> all_option_types;

  //contains all the UDP source ports
  vector<string> udp_sources;
  //contains all the UDP destination ports
  vector<string> udp_dests;

  //contains all the ICMP types
  vector<string> icmp_types;

  //contains all the ICMP codes
  vector<string> icmp_codes;

}pkt_t;

/*
This function simply prints out the help message and exits
*/
void help_message(){
  cout<<"*******************************************\n";
  cout<<"\t \t HELP SCREEN\n";
  cout<<"./wiretap [OPTIONS] file.pcap\n"
        "  --help            \t Print this help screen\n"
        "  --open filename   \t Show details of the packet capture\n";
  cout<<"*******************************************\n";
  exit(1);
}

/*
This function takes in a vector of sizes and computes their average

This function returns the average size
*/
double find_average_size(vector<int> sizes){
  double sum = 0.0;
  for(int i=0; i<sizes.size(); i++) sum += sizes[i];
  return sum / sizes.size();
}

/*
This function takes in a vector of sizes and computes their maximum

This function returns the maximum size
*/
int find_max_size(vector<int> sizes){
  int curr_max = 0;
  for(int i=0; i<sizes.size(); i++){
    if(sizes[i] > curr_max) curr_max = sizes[i];
  }
  return curr_max;
}

/*
This function takes in a vector of sizes and computes their minimum

This function returns the minimum size
*/
int find_min_size(vector<int> sizes){
  int curr_min = 999999;
  for(int i=0; i<sizes.size(); i++){
    if(sizes[i] < curr_min) curr_min = sizes[i];
  }
  return curr_min;
}

/*
This function takes in 2 timeval structures, and computes their difference

This function returns the difference with 2 decimal places of milliseconds
*/
int find_time_diff(timeval t1, timeval t2){
  int sec_diff_in_usec = (t1.tv_sec - t2.tv_sec) * 1000000;
  int usec_diff = t1.tv_usec - t2.tv_usec;
  int time_diff_in_usec = sec_diff_in_usec + usec_diff + 500;
    return time_diff_in_usec/10000; //return amount of seconds with 2 dp of milliseconds
}

/*
This function takes in a timeval structure, and parses it out

This function returns the a readable date and time with milliseconds in string format 
*/
string analyze_time(const struct timeval time){
  //Initializing structures, variables to get time and date
  struct timeval pkt_time = time;
  struct tm *current_time;
  char time_in_sec[64], time_in_usec[64];
  gettimeofday(&pkt_time, NULL);
  //Converting raw time into a time tm structure
  current_time = localtime(&time.tv_sec);
  //Converting tm structure into printable format
  strftime(time_in_sec, sizeof(time_in_sec), "%Y-%m-%d %H:%M:%S", current_time);
  //Appending microseconds to the printable time string
  snprintf(time_in_usec, sizeof(time_in_usec), "%s.%06d", time_in_sec, time.tv_usec);
  string full_date_and_time = time_in_usec;
  return full_date_and_time;
}


/*
This function takes in a vector of strings and a vector of integers and 
removes all duplicates from the first vector, while incrementing values 
in the second vector(counting the duplicates).

This function returns the first vector with no duplicates
*/
vector<string> find_unique(vector<string> address, vector<int> * count){
  vector<int>& count_address = *count;
  sort(address.begin(),address.end());
  for(int i=0;i<address.size();i++){
    count_address.push_back(1);
      if(i != (address.size()-1) && address[i] == address[i+1]){
        count_address[i]++;
        address.erase(address.begin()+i);
        i--;
      }
  }
  return address;
}

/*
This function takes in a vector of integers and another vector of integers and 
removes all duplicates from the first vector, while incrementing values 
in the second vector(counting the duplicates).

This function returns the first vector with no duplicates
*/
vector <int> find_unique_type(vector <int> type, vector<int> * count){
  vector <int>& count_type = *count;
  sort(type.begin(),type.end());
  for(int i=0;i<type.size();i++){
    count_type.push_back(1);
      if(type[i] == type[i+1] && i != (type.size()-1)){
        count_type[i]++;
        type.erase(type.begin()+i);
        i--;
      }
  }
  return type;
}

/*
This function is the callback function of the pcap_loop() function. This function
runs once for every single packet that is sniffed. The main goal of this function
is to save all information into a packets structure which will then be analyzed
after all packets have been sniffed. If the packet is corrupted, then it simply 
exits out of this function, and moves on to the next packet.
*/
void analyze_packet(u_char *args, const struct pcap_pkthdr *pkt_info, const u_char *pkt){
  pkt_t *file_struct= (pkt_t *) args;

  //Add the times and sizes to the pkt_t struct
  file_struct->times.push_back(pkt_info->ts);
  file_struct->sizes.push_back(pkt_info->len);

  //Get the ethernet header and assign it to the structure
  struct ethhdr *eth = (struct ethhdr *) pkt;

  //Get ethernet source/destination address, assign to the file structure
  char eth_source[(ETH_ALEN*2)+(ETH_ALEN)];//use MAC standard notation
  char eth_dest[(ETH_ALEN*2)+(ETH_ALEN)];

  snprintf(eth_source, sizeof(eth_source), "%02x:%02x:%02x:%02x:%02x:%02x",
        eth->h_source[0], eth->h_source[1], eth->h_source[2],
        eth->h_source[3], eth->h_source[4], eth->h_source[5]);
  snprintf(eth_dest, sizeof(eth_dest), "%02x:%02x:%02x:%02x:%02x:%02x",
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
        eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

  file_struct->eth_sources.push_back(eth_source);
  file_struct->eth_dests.push_back(eth_dest);
  file_struct->eth_types.push_back(ntohs(eth->h_proto));

  //Check if packet is corrupted
  char hex_max_length[MAX_PROTO_TYPE];
  sprintf(hex_max_length,"%x",ETH_DATA_LEN);
  //If the type is a packet length..
  if(ntohs(eth->h_proto) < atoi(hex_max_length)){
    //Make sure the size of the packet is at least packet length
    if(pkt_info->len < ntohs(eth->h_proto)) return;
  }
  

  //Sniff the IP Packet details
  if(ntohs(eth->h_proto)==ETH_P_IP){
    //Get the IP source and destination addresses, and save them into the structure
    struct iphdr *iph = (struct iphdr *)(pkt+ ETH_HLEN);

    struct in_addr address_in_src,address_in_dest;
    address_in_src.s_addr=iph->saddr;
    address_in_dest.s_addr=iph->daddr;
    file_struct->ip_src_address.push_back(inet_ntoa(address_in_src)); 
    file_struct->ip_dest_address.push_back(inet_ntoa(address_in_dest)); 

    //Get the IP TTLs and save them into the structure
    char ip_ttl[4];
    snprintf(ip_ttl, sizeof(ip_ttl), "%d", iph->ttl);
    file_struct->ip_TTL.push_back(ip_ttl);

    //Get the transport layer protocol type and save into the structure
    file_struct->ip_type.push_back(iph->protocol);

    //Get TCP Packet details
    if(iph->protocol == IPPROTO_TCP){
      //Get the TCP source and destination ports, and save them into the structure
      struct tcphdr *tcph = (struct tcphdr *)(pkt+ ETH_HLEN + (iph->ihl*4));
      char tcp_sport[8]; char tcp_dport[8];
      snprintf(tcp_sport, sizeof(tcp_sport), "%d", ntohs(tcph->source));
      snprintf(tcp_dport, sizeof(tcp_dport), "%d", ntohs(tcph->dest));
      file_struct->tcp_sources.push_back(tcp_sport);
      file_struct->tcp_dests.push_back(tcp_dport);

      if(tcph->urg == 1) file_struct->urg_flag++;
      if(tcph->ack == 1) file_struct->ack_flag++;
      if(tcph->psh == 1) file_struct->psh_flag++;
      if(tcph->rst == 1) file_struct->rst_flag++;
      if(tcph->syn == 1) file_struct->syn_flag++;
      if(tcph->fin == 1) file_struct->fin_flag++;

      struct tcphdr *tcp_end = (struct tcphdr *)(pkt+ ETH_HLEN + (iph->ihl*4)+ (tcph->doff*4));

      //increment header to options
      tcph++;
      //calculate the length of the options field
      unsigned long options_length = (unsigned long)tcp_end - (unsigned long)tcph;

      char * tcp_opt = (char *)tcph;

      int curr_ind = 0;//Index to traverse options
      int curr_type = 0;//Type of each option
      int curr_leng = 0;//Length of each option
      int next_type = 0;//Look-ahead to the next type
      bool found_noop = false; //True if packet has some No-Operation option
      while(curr_ind != options_length){
        curr_type = (int)tcp_opt[curr_ind];
        //Save all the option types
        if(curr_type != 0){
          if(curr_type == TCPOPT_NOP && !found_noop){
            file_struct->all_option_types.push_back(curr_type);
            found_noop = true;
          }
          else if(curr_type != TCPOPT_NOP){
            file_struct->all_option_types.push_back(curr_type);
          }
        }
        else
          break;
        //Increment the pointer to the next option type based on the option type length
        if(curr_type == TCPOPT_NOP){
          next_type = (int)tcp_opt[curr_ind+1];
          if(next_type == TCPOPT_NOP) curr_ind += 2;
          else curr_ind++;
        }
        else{
          curr_leng = (int)tcp_opt[curr_ind+1];
          curr_ind += curr_leng; 
        }
      }
    }
    //Get UDP Packet details
    if(iph->protocol == IPPROTO_UDP){
      //Get the UDP source and destination ports, and save them into the structure
      struct udphdr *udph = (struct udphdr *)(pkt+ ETH_HLEN + (iph->ihl*4));
      char udp_sport[8]; char udp_dport[8];
      snprintf(udp_sport, sizeof(udp_sport), "%d", ntohs(udph->source));
      snprintf(udp_dport, sizeof(udp_dport), "%d", ntohs(udph->dest));
      file_struct->udp_sources.push_back(udp_sport);
      file_struct->udp_dests.push_back(udp_dport);
    }

    //Get ICMP Packet details
    if(iph->protocol == IPPROTO_ICMP){
      //Get the ICMP types and codes and save them into the structure
      struct icmphdr *icmph = (struct icmphdr *)(pkt+ ETH_HLEN + (iph->ihl*4));
      char icmp_type[4]; char icmp_code[4];
      snprintf(icmp_type, sizeof(icmp_type), "%d", icmph->type);
      snprintf(icmp_code, sizeof(icmp_code), "%d", icmph->code);
      file_struct->icmp_types.push_back(icmp_type);
      file_struct->icmp_codes.push_back(icmp_code);
    }
  }
  //Sniff the ARP Packet details
  else if(ntohs(eth->h_proto)== ETH_P_ARP){
    //Get the ARP MAC(hardware) and IP source addresses, combine them, save into structure
    arphdr_t *arph = (struct arphdr_t *)(pkt+ETH_HLEN);
    char arp_MAC[(ETH_ALEN*2)+(ETH_ALEN)];//use MAC standard notation
    char arp_IP[15];//use MAC standard notation

    snprintf(arp_MAC, sizeof(arp_MAC), "%02x:%02x:%02x:%02x:%02x:%02x",
        arph->sha[0], arph->sha[1], arph->sha[2],
        arph->sha[3], arph->sha[4], arph->sha[5]);
    snprintf(arp_IP, sizeof(arp_IP), "%d.%d.%d.%d",
        arph->sip[0], arph->sip[1], arph->sip[2], arph->sip[3]);

    string arp_combo(arp_MAC);
    string arp_IA(arp_IP);
    string seperator = " / ";
    arp_combo.append(seperator);
    arp_combo.append(arp_IA);
    file_struct->arp_addr.push_back(arp_combo); 
  }

}

int main (int argc, char * argv[]){
  pkt_t pkts;

  //Initializing flags to 0
  pkts.urg_flag = pkts.ack_flag = pkts.psh_flag = 0;
  pkts.rst_flag = pkts.syn_flag = pkts.fin_flag = 0;

  int ch; //for the arguments
  bool OPEN_OPT = false;
  if(argc < 2) help_message();
  else{
    //Retrieve the options:
    while((ch = getopt(argc, argv, "-h-open")) != -1){ 
        switch(ch){
            case 'h':
                if(argc == 2) help_message();
                else{ 
                  cout<<"Invalid amount of arguments with --help!\n";
                  help_message();
                }
                break;
            case 'o':
                if(argc != 3) {
                  cout<<"Not Enough Arguments.\n";
                  help_message();
                }
                else{
                  OPEN_OPT = true;
                }
                break;
            default:  //with an unknown option
                break;
        }
    }
  }

  //The actual pcap file structure
  pcap_t * pcap_file;


  //Setting up error buffer
  char * file_error;
  file_error = (char *) malloc(PCAP_ERRBUF_SIZE+1);

  //For the link layer data link type (must be Ethernet in our case)
  int datalink_type = 0;

  // This is true when the packet capture file is over Ethernet
  bool IS_ETH = false;

  //If open option, then attempt to open the file, and check if Ethernet capture
  if(OPEN_OPT){
    pcap_file = pcap_open_offline(argv[2], file_error);
    if(pcap_file == NULL) cout<<"Opening file failed! Check file name and retry.\n";
    else{ 
      datalink_type = pcap_datalink(pcap_file);
      if(datalink_type == DLT_EN10MB) IS_ETH = true;
      else{
        cout<<"Packet capture doesn't provide Ethernet headers. Not supported\n";
        exit(1);
      }
    }
  }
  free(file_error);//free up allocated memory
  
  //Initializing variables related to summary section
  double capture_duration, average_size;
  int max_size, min_size;
  vector<string> date_and_time;

  if(IS_ETH){//If the capture has Ethernet headers
    //Callback analyze_packet for every packet sniffed
    int pkt_loop = pcap_loop(pcap_file, NEGATIVE_VALUE, analyze_packet, (u_char *) &pkts);
    //All packets have been read

    //Convert the timeval structs into readable string format
    for(int i=0;i<pkts.times.size(); i++){
      date_and_time.push_back(analyze_time(pkts.times[i]));
    }
    //Call various functions to analyze the times and sizes collected
    capture_duration = find_time_diff(pkts.times.back(),pkts.times.front()) / 100.0;

    average_size = find_average_size(pkts.sizes);
    max_size = find_max_size(pkts.sizes);
    min_size = find_min_size(pkts.sizes);
    //Print out the data
    cout<<"\n========Packet Capture Summary========\n";
    cout<<"Capture start time: "<<date_and_time.front()<<" EDT"<<endl;
    cout<<"Capture duration: "<<capture_duration<<" seconds"<<endl;
    cout<<"Packets in capture: "<<pkts.times.size()<<endl;
    cout<<"Minimum packet size: "<<min_size<<endl;
    cout<<"Maximum packet size: "<<max_size<<endl;
    cout<<"Average packet size: "<<average_size<<endl<<endl;

    //Remove and count duplicates for source and destination ethernet addresses
    vector<int> count_src, count_dest;
    vector<string> unique_src_addr=find_unique(pkts.eth_sources,&count_src);
    vector<string> unique_dest_addr=find_unique(pkts.eth_dests,&count_dest);

    //Print out the unique Ethernet addresses and their count
    cout<<"\n==============Link Layer==============\n";
    cout<<"\n-----Source Ethernet Addresses-----\n";
    if(unique_src_addr.size() == 0) cout<<"{No Results}\n";
    for(int i=0;i<unique_src_addr.size();i++)cout<<unique_src_addr[i]<<"\t \t \t \t"<<count_src[i]<<endl;
    cout<<"\n---Destination Ethernet Addresses---\n";
    if(unique_dest_addr.size() == 0) cout<<"{No Results}\n";
    for(int j=0;j<unique_dest_addr.size();j++)cout<<unique_dest_addr[j]<<"\t \t \t \t"<<count_dest[j]<<endl;

    //removing and counting the protocol type duplicates and printing their types
    vector<int> count_types;
    vector<int> unique_types=find_unique_type(pkts.eth_types,&count_types);
    char hex_type[MAX_PROTO_TYPE];
    char hex_max_length[MAX_PROTO_TYPE];//used to get hex of 1500
    cout<<"\n==============Network Layer==============\n";
    cout<<"\n-------Network Layer Protocols-------\n";
    if(unique_types.size() == 0) cout<<"{No Results}\n";
    for(int k=0; k<unique_types.size(); k++){
      sprintf(hex_type,"%x",unique_types[k]);
      sprintf(hex_max_length,"%x",ETH_DATA_LEN);
      if(unique_types[k] < atoi(hex_max_length)){
        cout<<"~~~Packet Length~~~\n";
        cout<<unique_types[k]<<" (0x"<<hex_type<<")"<<"\t \t \t"<<count_types[k]<<endl;
        cout<<"~~~~~~~~~~~~~~~~~~~\n";
      }
      else if(unique_types[k] < ETH_P_IP || unique_types[k] == ETH_P_IPV6){ 
        cout<<unique_types[k]<<" (0x"<<hex_type<<")"<<"\t \t \t"<<count_types[k]<<endl;
      }
      else if(unique_types[k] == ETH_P_IP) cout<<"IP"<<"\t \t \t \t"<<count_types[k]<<endl;
      else if(unique_types[k] == ETH_P_ARP) cout<<"ARP"<<"\t \t \t \t"<<count_types[k]<<endl;
    }

    //Print out the unique IP addresses and their count
    vector<int> count_src_ip;
    cout<<"\n-----Source IP Addresses-----\n";
    vector<string> unique_src_ip=find_unique(pkts.ip_src_address,&count_src_ip);
    if(unique_src_ip.size() == 0) cout<<"{No Results}\n";
    for(int i=0;i<unique_src_ip.size();i++)cout<<unique_src_ip[i]<<"\t \t \t \t"<<count_src_ip[i]<<endl;

    vector<int> count_dest_ip;
    cout<<"\n-----Destination IP Addresses-----\n";
    vector<string> unique_dest_ip=find_unique(pkts.ip_dest_address,&count_dest_ip);
    if(unique_dest_ip.size() == 0) cout<<"{No Results}\n";
    for(int i=0;i<unique_dest_ip.size();i++)cout<<unique_dest_ip[i]<<"\t \t \t \t"<<count_dest_ip[i]<<endl;

    //Print out the unique TTLs and their count
    cout<<"\n--------IP Time-To-Lives--------\n";
    vector<int> count_ip_ttl;
    vector<string> unique_ip_ttl = find_unique(pkts.ip_TTL, &count_ip_ttl);
    if(unique_ip_ttl.size() == 0) cout<<"{No Results}\n";
    for(int i=0;i<unique_ip_ttl.size();i++)cout<<unique_ip_ttl[i]<<"\t \t \t \t"<<count_ip_ttl[i]<<endl;

    //Print out the unique ARP participants and how many times they participated
    vector<int> count_arp_addr;
    cout<<"\n-----Unique ARP Participants-----\n";
    vector<string> unique_arp_addr = find_unique(pkts.arp_addr, &count_arp_addr);
    if(unique_arp_addr.size() == 0) cout<<"{No Results}\n";
    for(int i=0;i<unique_arp_addr.size();i++)cout<<unique_arp_addr[i]<<"\t \t"<<count_arp_addr[i]<<endl;

    cout<<"\n==============Transport Layer==============\n";
    cout<<"\n-------Transport Layer Protocols-------\n";
    //removing and counting the protocol type duplicates and printing their types
    vector<int> count_ip_types;
    vector<int> unique_ip_types=find_unique_type(pkts.ip_type,&count_ip_types);
    if(unique_ip_types.size() == 0) cout<<"{No Results}\n";
    for(int k=0; k<unique_ip_types.size(); k++){
      if(unique_ip_types[k] == IPPROTO_TCP) cout<<"TCP"<<"\t \t \t \t"<<count_ip_types[k]<<endl;
      else if(unique_ip_types[k] == IPPROTO_UDP) cout<<"UDP"<<"\t \t \t \t"<<count_ip_types[k]<<endl;
      else if(unique_ip_types[k] == IPPROTO_ICMP) cout<<"ICMP"<<"\t \t \t \t"<<count_ip_types[k]<<endl;
      else cout<<unique_ip_types[k]<<"\t \t \t \t"<<count_ip_types[k]<<endl;
    }
    cout<<"\n=======Transport Layer--TCP--=======\n";
    //Print out the unique TCP ports and their count
    vector<int> count_tcp_sport;
    cout<<"\n-----TCP Source Ports-----\n";
    vector<string> unique_tcp_sport = find_unique(pkts.tcp_sources,&count_tcp_sport);
    if(unique_tcp_sport.size() == 0) cout<<"{No Results}\n";
    for(int i=0;i<unique_tcp_sport.size();i++)cout<<unique_tcp_sport[i]<<"\t \t \t \t"<<count_tcp_sport[i]<<endl;

    vector<int> count_tcp_dport;
    cout<<"\n----TCP Destination Ports----\n";
    vector<string> unique_tcp_dport= find_unique(pkts.tcp_dests,&count_tcp_dport);
    if(unique_tcp_dport.size() == 0) cout<<"{No Results}\n";
    for(int i=0;i<unique_tcp_dport.size();i++)cout<<unique_tcp_dport[i]<<"\t \t \t \t"<<count_tcp_dport[i]<<endl;

    //Print out the number of packets with specific flags
    cout<<"\n---------TCP Flags---------\n";
    if((pkts.urg_flag + pkts.ack_flag + pkts.psh_flag + pkts.rst_flag + pkts.syn_flag + pkts.fin_flag) == 0)
      cout<<"{No Results}\n\n";
    else{
      cout<<"URG \t \t \t \t"<<pkts.urg_flag<<endl;
      cout<<"ACK \t \t \t \t"<<pkts.ack_flag<<endl;
      cout<<"PSH \t \t \t \t"<<pkts.psh_flag<<endl;
      cout<<"RST \t \t \t \t"<<pkts.rst_flag<<endl;
      cout<<"SYN \t \t \t \t"<<pkts.syn_flag<<endl;
      cout<<"FIN \t \t \t \t"<<pkts.fin_flag<<endl;
    }

    //Print out the number of packets using specific options
    vector<int> count_tcp_options;
    char hex_tcp_opt[MAX_PROTO_TYPE];
    cout<<"----------TCP Options-------\n";
    vector<int> unique_tcp_options = find_unique_type(pkts.all_option_types, &count_tcp_options);
    if(unique_tcp_options.size() == 0) cout<<"{No Results}\n";
    for(int i=0;i<unique_tcp_options.size(); i++){
      sprintf(hex_tcp_opt,"%x",unique_tcp_options[i]);
      cout<<unique_tcp_options[i]<<" (0x"<<hex_tcp_opt<<")"<<"\t \t \t \t"<<count_tcp_options[i]<<endl;
    }

    cout<<"\n=======Transport Layer--UDP--=======\n";
    //Print out the unique UDP ports and their count
    vector<int> count_udp_sport;
    cout<<"\n-----UDP Source Ports-----\n";
    vector<string> unique_udp_sport = find_unique(pkts.udp_sources,&count_udp_sport);
    if(unique_udp_sport.size() == 0) cout<<"{No Results}\n";
    for(int i=0;i<unique_udp_sport.size();i++)cout<<unique_udp_sport[i]<<"\t \t \t \t"<<count_udp_sport[i]<<endl;

    vector<int> count_udp_dport;
    cout<<"\n----UDP Destination Ports----\n";
    vector<string> unique_udp_dport= find_unique(pkts.udp_dests,&count_udp_dport);
    if(unique_udp_dport.size() == 0) cout<<"{No Results}\n";
    for(int i=0;i<unique_udp_dport.size();i++)cout<<unique_udp_dport[i]<<"\t \t \t \t"<<count_udp_dport[i]<<endl;

    //Print out the uniqye ICMP types and codes used
    cout<<"\n=======Transport Layer--ICMP--=======\n";
    vector<int> count_icmp_types;
    cout<<"\n--------ICMP Types--------\n";
    vector<string> unique_icmp_type = find_unique(pkts.icmp_types,&count_icmp_types);
    if(unique_icmp_type.size() == 0) cout<<"{No Results}\n";
    for(int i=0; i<unique_icmp_type.size();i++)cout<<unique_icmp_type[i]<<"\t \t \t \t"<<count_icmp_types[i]<<endl;

    vector<int> count_icmp_codes;
    cout<<"\n--------ICMP Codes--------\n";
    vector<string> unique_icmp_code = find_unique(pkts.icmp_codes,&count_icmp_codes);
    if(unique_icmp_code.size() == 0) cout<<"{No Results}\n";
    for(int i=0; i<unique_icmp_code.size();i++)cout<<unique_icmp_code[i]<<"\t \t \t \t"<<count_icmp_codes[i]<<endl;

    cout<<"\n*******************************\n";

  }

  //Close the pcap file after done
  if(IS_ETH) pcap_close(pcap_file);
  return 0;
}
