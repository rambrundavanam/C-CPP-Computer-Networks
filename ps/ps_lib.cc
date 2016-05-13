#include <netinet/in.h>
#include <netinet/ip.h> //ip hdeader library (must come before ip_icmp.h)
#include <netinet/ip_icmp.h> //icmp header
#include <netinet/ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <pcap/pcap.h>
#include <pcap/bpf.h>
#include <linux/if_ether.h>
#include <cerrno>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <pthread.h>
#include <getopt.h>
#include <strings.h>

#include "ps_lib.h"

using namespace std;

/*
 This is the coolest function. It returns a random number from 0 to any given
 number specified.
*/
int random_port(int max_number){
  return rand() % max_number;
}

/*
Finds the 1's complement of the 1's complement sum of all 16-bit words and returns
the checksum as a 16 bit.
*/
uint16_t IP_checksum(uint16_t* data, int size){
  uint32_t total = 0;
  uint16_t checksum = 0;
  int i;
  //Add 16-bit words together
  for(i=0; i<(size/2); i++){ 
    total += data[i];
    //Add the 16 low bits, to the 16 high bits, including the carry
    while((total>>16) != 0){
      total = (total & 0xFFFF) + (total >> 16);
    }
  }
  //Now we have the 1s-complement sum of the 16 bit words
  //Now take the 1s-complement of that, and shorten it to only 16 bits.
  checksum = (uint16_t) ~total;
  return checksum;
}

/*
This is the UDP Checksum as outlined in the RFC 768 guidelines.
*/
uint16_t UDP_checksum(iphdr *iph, udphdr *udph){
  //Create a pseudo header
  pseudo_header ps_hdr;
  //Create a 'packet' to save everything to
  char my_packet[IPMAXPACKET];

  //Fill in the pseudo header
  ps_hdr.source_ip = iph->saddr;
  ps_hdr.dest_ip = iph->daddr;
  ps_hdr.reserved = 0;
  ps_hdr.protocol = IPPROTO_UDP;
  ps_hdr.length = udph->len;
  //ps_hdr.length = htons(sizeof(udphdr));//Only header length because no data

  //Add the Pseudo Header into our packet
  memcpy(my_packet, &ps_hdr, sizeof(ps_hdr));

  //Add the UDP Header into our packet
  memcpy(my_packet+sizeof(pseudo_header), udph, sizeof(udphdr));

  //Find the 16 bit one's complement of the one's complement sum of all 16-bit words(as outlined in RFC 793)
  uint16_t udp_checksum = IP_checksum((uint16_t *)my_packet, sizeof(udphdr) + sizeof(pseudo_header));

  return udp_checksum; 
}

/*
This is the TCP Checksum as outlined in the RFC 793 guidelines.
*/
uint16_t TCP_checksum(iphdr *iph, tcphdr *tcph){
  //Create a pseudo header
  pseudo_header ps_hdr;
  //Create a 'packet' to save everything to
  char my_packet[MAX_TCP_PACKET_SIZE];

  //Fill in the pseudo header
  ps_hdr.source_ip = iph->saddr;
  ps_hdr.dest_ip = iph->daddr;
  ps_hdr.reserved = 0;
  ps_hdr.protocol = IPPROTO_TCP;
  ps_hdr.length = htons(sizeof(tcphdr));//Only header length because no data

  //Add the Pseudo Header into our packet
  memcpy(my_packet, &ps_hdr, sizeof(ps_hdr));

  //Add the TCP Header into our packet
  memcpy(my_packet+sizeof(pseudo_header), tcph, sizeof(tcphdr));

  //Find the 16 bit one's complement of the one's complement sum of all 16-bit words(as outlined in RFC 793)
  uint16_t tcp_checksum = IP_checksum((uint16_t *)my_packet, sizeof(tcphdr) + sizeof(pseudo_header));

  return tcp_checksum; 
}

/*
 Determines the interface name of the NIC. Returns the interface name.
*/
string get_interface_name(){
  struct ifaddrs * ifaddr;
  bzero(&ifaddr, sizeof(ifaddr));
  if(getifaddrs(&ifaddr) != -1){
    ifaddr = ifaddr->ifa_next;
    ifaddr = ifaddr->ifa_next;
    return string(ifaddr->ifa_name);
  }
  freeifaddrs(ifaddr);
}

/*
 Given a socket, and interface name, this function will return the IP address
*/
string get_interface_IP(int socket){
  struct ifreq addr;

  string interFaceName= get_interface_name();

  memset(&addr, 0, sizeof(addr));
  size_t length=strlen(interFaceName.c_str());
  if( length-1< sizeof(addr.ifr_name)){
    memcpy(addr.ifr_name,interFaceName.c_str(),length);
    addr.ifr_name[length]='\0';
  }
  else
    cout<<"Interface name error!\n";
  if(ioctl(socket,SIOCGIFADDR,&addr)==-1){
    cout<<"Error getting source IP address!"<<errno<<endl;
    cout<<EBADF<<" "<<EFAULT<<" "<<EINVAL<<" "<<ENOTTY<<endl;
    perror("The following error occured");
  }
  struct sockaddr_in *saddr=(struct sockaddr_in *)&addr.ifr_addr;
  string sourceIP=inet_ntoa(saddr->sin_addr);
  return sourceIP;
}

/*
 pthread_create callback function. Calls the pcap_sniffer, and listens for packets.
*/
void* thread_sniffer(void * arg){
  struct temp_target * target = (struct temp_target *) arg;
  string ifname = get_interface_name();
  pcap_sniffer((char *)ifname.c_str(), target);
}

/*
 Sends a TCP packet based on the Destination & Source IPs and Ports
*/
void send_TCP(int socket, struct ps_source source, string destIP, int destPort, string scan_type){
  int packet_length = 4096;
  char packet[packet_length];

  //Parse out the source IP and Port
  string sourceIP = source.IP;
  int sourcePort = source.port;

  struct iphdr *iph = (struct iphdr *) packet;
  //struct tcphdr *tcph = (struct tcphdr *) packet + sizeof(struct iphdr);
  struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
  //intialize our packet
  memset(packet, 0, packet_length);

  //Assign IPv4 Header values
  iph->ihl = 5; //20 byte IP header
  iph->version = 4; //for IPv4
  iph->tos = 0;//Best effort type of service
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
  //cout<<"Total Packet Length: "<<iph->tot_len<<endl;
  iph->id = htons(random_port(10000)); //some random ID number
  iph->frag_off = 0; //fragmentation offset
  iph->ttl = 64; //default value for ttl
  iph->protocol = IPPROTO_TCP; //tcp protocol number
  iph->check = 0; 
  iph->saddr = inet_addr(sourceIP.c_str());
  iph->daddr = inet_addr(destIP.c_str());

  //Assign TCP Header values
  tcph->source = htons(sourcePort); //source port
  tcph->dest = htons(destPort); //destination port

  //Set only Syn Flag
  tcph->urg = 0; //TCP Urgent
  tcph->ack = 0; //TCP Ack
  tcph->psh = 0; //TCP Push
  tcph->rst = 0; //TCP Reset
  tcph->fin = 0; //TCP Finish
  tcph->syn = 0; //TCP SYN
  if(scan_type == "SYN") tcph->syn = 1;
  else if(scan_type == "ACK") tcph->ack = 1;
  else if(scan_type == "FIN") tcph->fin = 1;
  else if(scan_type == "XMAS"){
    tcph->fin = 1;
    tcph->psh = 1;
    tcph->urg = 1;
  }
  tcph->res1 = 0; //Disregard reserve bits
  tcph->res2 = 0;
  tcph->seq = htonl(random_port((int) pow(2.0,32.0))); //Random sequence number
  tcph->ack_seq = htonl(0);
  tcph->doff = sizeof(struct tcphdr)/4; // Indicating no options or data, set to 5 for default
  tcph->urg_ptr = 0; //Not needed
  tcph->window = ntohs(65535); //Maximum window
  tcph->check = 0; //Relying on OS to fill in this checksum

  //Calculate the checksums
  tcph->check = TCP_checksum(iph, tcph);
  iph->check = IP_checksum((unsigned short *)packet, iph->tot_len);

  int buffer = 1;
  //Tell the OS to not fill in the IP Header by setting the IP_HDRINCL option
  if(setsockopt(socket, IPPROTO_IP, IP_HDRINCL, (const char *)&buffer, sizeof(buffer)) < 0){
    cout<<"HDRINCL fail.\n";
    exit(-1);
  }

  //This will be used for destination addresses
  struct sockaddr_in dest;
  //Declare that the addresses are IPv4
  dest.sin_family = AF_INET;
  //Assign the source and destination ports
  dest.sin_port = destPort;
  //Assign the source and destination addresses
  dest.sin_addr.s_addr = inet_addr(destIP.c_str());

  //Send the created packet
  if(sendto(socket, packet, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0){
    cout<<"Sending TCP Packet failed!\n";
    exit(-1);
  }
}

/*
 The callback function for pcap_loop. Runs once for every packet sniffed, parses the packet,
 and sets the results.
*/
void pcap_parse(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet){

  //Get Target structure
  struct temp_target * target = (struct temp_target *)user;

  //Get Ethernet Header
  struct ethhdr *eth = (struct ethhdr *)packet;

  //Get the IP Header
  struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));

  //Get the TCP Header
  struct tcphdr * tcph = (struct tcphdr *)(packet + (iph->ihl*4) + sizeof(struct ethhdr));

  //Get the UDP Header
  struct udphdr * udph = (struct udphdr *)(packet + (iph->ihl*4) + sizeof(struct ethhdr));

  //Get the ICMP Header
  struct icmphdr * icmph = (struct icmphdr *)(packet + (iph->ihl*4) + sizeof(struct ethhdr));

  //Get the Source and Destination addresses
  struct in_addr adr_in_src,adr_in_dest;
  
  memset(&adr_in_src,0,sizeof(adr_in_src));
  adr_in_src.s_addr = iph->saddr;
  
  memset(&adr_in_dest,0,sizeof(adr_in_dest));
  adr_in_dest.s_addr = iph->daddr;
  
  //convert the string ip to a machine format
  struct in_addr d_ip;
  d_ip.s_addr=inet_addr((target->IP).c_str());
  
  //Make sure its an IPv4 Packet
  if(ntohs(eth->h_proto) == ETH_P_IP){
     
    //check the type of scan
    if(target->scan_type=="SYN"){

      //Make sure its a TCP Packet
      if(iph->protocol== IPPROTO_TCP){ 

        //Make sure if the packet is intended to us
        if(adr_in_src.s_addr == d_ip.s_addr  && ntohs(tcph->source) == target->port){

        //Check if it's a SYNACK
          if((unsigned int)tcph->syn == 1 && (unsigned int)tcph->ack == 1){
                  target->result = 1;//Set Port to Open
                }
          else if(tcph->rst == 1){
              target->result = 2;//Set Port to Closed 
            }

          else if(tcph->syn == 1 && tcph->ack == 0){
              target->result = 1;//Set Port to Open
            }
          }
        }
        else if(iph->protocol == IPPROTO_ICMP && adr_in_src.s_addr == d_ip.s_addr){
          if(icmph->type == 3 && (icmph->code == 1 || icmph->code == 2 || icmph->code == 3 || icmph->code == 9 || icmph->code == 10 || icmph->code == 13)){
                target->result = 3; //Set to Filtered
              }
            }
      }

        //check the type of scan
    else if(target->scan_type=="ACK"){
      //Make sure its a TCP Packet
      if(iph->protocol== IPPROTO_TCP){ 
      //Make sure if the packet is intended to us
       if(adr_in_src.s_addr == d_ip.s_addr  && ntohs(tcph->source) == target->port){
          if(tcph->rst == 1){
              target->result = 4;
            }
          }
        }
        else if(iph->protocol == IPPROTO_ICMP && adr_in_src.s_addr == d_ip.s_addr){
          if(icmph->type == 3 && (icmph->code == 1 || icmph->code == 2 || icmph->code == 3 || icmph->code == 9 || icmph->code == 10 || icmph->code == 13)){
                target->result = 3;
              }
            }
    }
    else if(target->scan_type == "FIN" || target->scan_type == "NULL" || target->scan_type == "XMAS"){
      if(iph->protocol == IPPROTO_TCP){
        if(adr_in_src.s_addr == d_ip.s_addr && ntohs(tcph->source) == target->port){
          if(tcph->rst == 1){
            target->result = 2; //Port is closed
          }
        }
      }
      else if(iph->protocol == IPPROTO_ICMP && adr_in_src.s_addr == d_ip.s_addr){
        if(icmph->type == 3 && (icmph->code == 1 || icmph->code == 2 || icmph->code == 3 || icmph->code == 9 || icmph->code == 10 || icmph->code == 13)){
          target->result = 3; //Port is filtered
        }
      }
    }
    else if(target->scan_type == "UDP"){
      if(iph->protocol== IPPROTO_UDP){ 
        if(adr_in_src.s_addr == d_ip.s_addr && ntohs(udph->source) == target->port){
          target->result = 1;//Open Port
        }
      }
      else if(iph->protocol == IPPROTO_ICMP){
        if(adr_in_src.s_addr == d_ip.s_addr){
          if(icmph->type == 3 && (icmph->code == 1 || icmph->code == 2 || icmph->code == 9 || icmph->code == 10 || icmph->code == 13)){
            target->result = 3;//Filtered baby woohoo
          }        
          else if (icmph->type == 3  && icmph-> code == 3){
            target->result = 2;//Port is closed
          }
        }
      }   
    }  
  }
}

/*
 Initializes pcap capture, and calls pcap_loop() which will sniff the packets.
*/
void pcap_sniffer(char * interface, struct temp_target * target){
  char error[PCAP_ERRBUF_SIZE];

  //Open the interface to sniff packets
  pcap_t* pcap_desc = pcap_open_live(interface, BUFSIZ,1,0,error);
  if(pcap_desc == NULL){
    cout<<"Failed to open the interface with error: "<<error<<". Exiting.\n";
    exit(1);
  }
  //Get the IP & mask of the interface we're sniffing on
  uint32_t sourceIP, mask;
  if(pcap_lookupnet(interface, &sourceIP, &mask, error) < 0){
    cout<<"Failed to get IP & Mask with error: "<<error<<". Exiting.\n";
    exit(1);
  }
  //Sniff the packets
  if(pcap_loop(pcap_desc, -1, pcap_parse, (u_char *) target)  == -1){
    cout<<"Failed to sniff the packets! Exiting.\n";
    exit(-1);
  }
  pcap_close(pcap_desc);
}

/*
 Sends a UDP packet based on the Destination & Source IPs and Ports
*/
void send_UDP(int socket, struct ps_source source, string destIP, int destPort){
  
  //For all ports except DNS
  if(destPort!=53){
    int packet_length = 65536;
    char packet[packet_length];

    //Parse the source IP and Port
    string sourceIP = source.IP;
    int sourcePort = source.port;

    struct iphdr *iph = (struct iphdr *) packet;
    
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    
    //initialize our packet
    memset(packet, 0, packet_length);

    //Assign IPv4 Header values
    iph->ihl = 5; //20 byte IP header
    iph->version = 4; //for IPv4
    iph->tos = 0;//Best effort type of service
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
    iph->id = htons(random_port(10000)); //some random ID number
    iph->frag_off = 0; //fragmentation offset
    iph->ttl = 64; //default value for ttl
    iph->protocol = IPPROTO_UDP; //tcp protocol number
    iph->check = 0; 
    iph->saddr = inet_addr(sourceIP.c_str());
    iph->daddr = inet_addr(destIP.c_str());

    udph->source = htons(sourcePort);
    udph->dest = htons(destPort);
    udph->len = htons(sizeof(struct udphdr));
    udph->check = 0;

    //Calculate checksums
    udph->check = UDP_checksum(iph, udph);
    iph->check = IP_checksum((unsigned short *)packet, iph->tot_len);

    int buffer = 1;
    //Tell the OS to not fill in the IP Header by setting the IP_HDRINCL option
    if(setsockopt(socket, IPPROTO_IP, IP_HDRINCL, (const char *)&buffer, sizeof(buffer)) < 0){
      cout<<"HDRINCL fail.\n";
      exit(-1);

    }

    //This will be used for destination address
    struct sockaddr_in dest;

    //Declare that unsignedthe addresses are IPv4
    dest.sin_family = AF_INET;
    
    //Assign the destination port
    dest.sin_port = destPort;
    
    //Assign the destination addresses
    dest.sin_addr.s_addr = inet_addr(destIP.c_str());

    //Send the created packet
    if(sendto(socket, packet, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0){
      cout<<"Sending UDP Packet failed!\n";
      exit(-1);
    }
  }
  //For DNS Port
  else {      
    int packet_length = 65536;
    char packet[packet_length];
    unsigned char quEry[16]={3,'w','w','w',6,'g','o','o','g','l','e',3,'c','o','m',0};

    //Parse the source IP and Port
    string sourceIP = source.IP;
    int sourcePort = source.port;

    struct udphdr *udph = (struct udphdr *)packet;
    
    struct dnshdr *DNSHDR = (struct dnshdr *)(packet + sizeof(struct udphdr));
    
    struct question * q_info = (struct question*) (packet+ sizeof(struct udphdr) + sizeof(struct dnshdr) +16);

    //initialize our packet
    memset(packet, 0, packet_length);
    //create a packet for dns query on port 53
    udph->source = htons(sourcePort);
    udph->dest = htons(53);
    udph->check=0;
    udph->len=htons(sizeof(struct udphdr)+sizeof(struct dnshdr)+sizeof(struct question)+16);

    //DNS header initialization 
    DNSHDR->id = htons(random_port(10000)); 
    DNSHDR->opcode = 0;//standard query
    DNSHDR->qr = 0;//query
    DNSHDR->aa = 0;//NON AUTHORITATIVE
    DNSHDR->tc = 0;//not trundacted
    DNSHDR->rd = 1;//yes for recursion
    DNSHDR->ra = 0;//no recursion available from us
    DNSHDR->z = 0;
    DNSHDR->ad = 0;
    DNSHDR->cd = 0;
    DNSHDR->rcode = 0;
    DNSHDR->q_count = htons(1);
    DNSHDR->ans_count = 0;
    DNSHDR->auth_count = 0;
    DNSHDR->add_count = 0;
      
    memcpy(packet+ sizeof(struct udphdr) + sizeof(struct dnshdr),quEry,16);

    //This will be used for destination address
    struct sockaddr_in dest;

    //Declare that unsignedthe addresses are IPv4
    dest.sin_family = AF_INET;
    
    //Assign the destination port
    dest.sin_port = htons(53);
    
    //Assign the destination addresses
    dest.sin_addr.s_addr = inet_addr(destIP.c_str());

    q_info->q_type = htons(1);
    q_info->q_class = htons(1);

    //Send the created packet
    if(sendto(socket, packet, sizeof(struct udphdr) + sizeof(struct dnshdr) + (strlen((const char*) quEry) + 1) + sizeof(struct question), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0){
      cout<<"Sending UDP Packet failed!\n";
      exit(-1);
    }    
  }
}

/*
 Takes in a protocol, and creates a raw socket based on that protocol.
 Returns the socket descriptor
*/
int create_raw_socket(int protocol){
  //int sock_desc = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW); //change to AF_INET if trouble..
  int sock_desc = socket(AF_INET, SOCK_RAW, protocol);
  if(sock_desc < 0){
    cout<<"Error in creating the Raw Socket."<<endl;
    exit(0);
  }
  else {
  //cout<<"\nCreated a Raw Socket to start the Scan."<<endl;
  return sock_desc;
  }
}

/*
 Returns true if the target IP:port pair has already been concluded. False otherwise.
*/
bool target_exists(vector<string> IPs, string IP, vector<int> ports, int port){
  bool IP_exists = false;
  bool port_exists = false;
  for(int i=0; i<IPs.size(); i++){
    if(IPs[i] == IP) IP_exists = true;
  }
  for(int k=0; k<ports.size(); k++){
    if(ports[k] == port) port_exists = true;
  }
  if(port_exists && IP_exists) return true;
  else return false;
}

/*
 Draws conclusions about the IP:Port pairs, given the different results from the 
 various scan types. Prints out the conclusion.
*/
void decide_status(vector<struct temp_target> final_tgts, vector<string> scan_types){
  bool syn_exists = false;
  bool ack_exists = false;
  bool udp_exists = false;
  bool xnf_exists = false;
  for(int i=0; i< scan_types.size(); i++){
    if(scan_types[i] == "SYN") syn_exists = true;
    else if(scan_types[i] == "ACK") ack_exists = true;
    else if(scan_types[i] == "UDP") udp_exists = true;
    else if(scan_types[i] == "FIN" || scan_types[i] == "NULL" || scan_types[i] == "XMAS") xnf_exists = true;
  }
  cout<<"\nConclusions\n";
  cout<<"---------------\n";
  bool five_exists = false;
  bool three_exists = false;
  bool one_exists = false;
  vector<string> displayed_IPs;
  vector<int> displayed_ports;
  for(int i=0; i<final_tgts.size(); i++){
    string result;
    if(final_tgts[i].result == 1) result = "Open";
    else if(final_tgts[i].result == 2) result = "Closed";
    else if(final_tgts[i].result == 3) result = "Filtered";
    else if(final_tgts[i].result == 4) result = "Unfiltered";
    else if(final_tgts[i].result == 5) result = "Open | Filtered";
    if(final_tgts[i].scan_type == "SYN"){
      cout<<"IP Address: "<<final_tgts[i].IP<<" at Port: "<<final_tgts[i].port<<" is "<<"("<<result<<")"<<endl<<endl;
      displayed_IPs.push_back(final_tgts[i].IP);
      displayed_ports.push_back(final_tgts[i].port);
    }
    else if(final_tgts[i].scan_type == "UDP" && !syn_exists){
      cout<<"IP Address: "<<final_tgts[i].IP<<" at Port: "<<final_tgts[i].port<<" is "<<"("<<result<<")\n\n";
      displayed_IPs.push_back(final_tgts[i].IP);
      displayed_ports.push_back(final_tgts[i].port);
    }
    else if(final_tgts[i].scan_type == "ACK" && !syn_exists && !udp_exists){
      cout<<"IP Address: "<<final_tgts[i].IP<<" at Port: "<<final_tgts[i].port<<" is "<<"("<<result<<")\n\n";
      displayed_IPs.push_back(final_tgts[i].IP);
      displayed_ports.push_back(final_tgts[i].port);
    }
    else if(xnf_exists && !syn_exists && !udp_exists && !ack_exists){
      cout<<"IP Address: "<<final_tgts[i].IP<<" at Port: "<<final_tgts[i].port<<" is "<<"("<<result<<")\n\n";
      displayed_IPs.push_back(final_tgts[i].IP);
      displayed_ports.push_back(final_tgts[i].port);
    }
  }
}

/*
 Takes in a IP:Port pair, and verifies if the given port service is running on the host IP.
 It returns the service version.
*/
string verify_services(string IP, int port){
  const int SSH_PORT = 22;
  const int HTTP_PORT = 80;
  const int WHOIS_PORT = 43;
  const int POP_PORT = 110;
  const int IMAP_PORT = 143;
  bool SMTP_PORT = false;

  if(port == 24 || port == 25 || port == 587) SMTP_PORT = true;

  //Create a TCP socket
  int sock_desc;
  sock_desc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(sock_desc == -1){
    cout<<"Creating the socket failed\n";
    exit(-1);
  }

  //This will be used for destination address
  struct sockaddr_in dest;
  //Declare that unsigned the addresses are IPv4
  dest.sin_family = AF_INET;
  //Assign the destination port
  dest.sin_port = htons(port);
  //Assign the destination addresses
  dest.sin_addr.s_addr = inet_addr(IP.c_str());

  //Establish the TCP socket connection
  int connect_desc;
  connect_desc = connect(sock_desc,(sockaddr *) &dest, sizeof(dest));
  if(connect_desc != 0){
    cout<<"Failed to connect to "<<IP<<" at port "<<port<<endl;
    exit(-1);
  }

  char packet[1024];
  int packet_size;
 
  //Verifying Services
  if(port == SSH_PORT){
    packet_size = recv(sock_desc,packet, 1024, 0);
    string version_num(packet);
    int ver_start=version_num.find("SSH");
    int ver_end=version_num.find("\n",ver_start+1);
    string version = version_num.substr(ver_start,ver_end-ver_start);
    close(sock_desc);
    return version;
  }
  else if(port == HTTP_PORT){
      string get_message = "GET /mail HTTP/1.1\nHOST:";
      get_message.append(IP);
      get_message.append("\n\n");
      send(sock_desc, get_message.c_str(), strlen(get_message.c_str()), 0);
      packet_size = recv(sock_desc,packet, 1024, 0);
      string version_num(packet);
      int ver_start=version_num.find("Server:");
      int ver_end=version_num.find("\n",ver_start+1);
      string version=version_num.substr(ver_start,ver_end-ver_start);
      close(sock_desc);
      return version;
  }
  else if(port == WHOIS_PORT){
      string whois_query = "google.com\n\n";
      send(sock_desc, whois_query.c_str(), strlen(whois_query.c_str()), 0);
      packet_size = recv(sock_desc,packet, 1024, 0);
      string version_num(packet);
      int ver_start = version_num.find("Whois Server Version");
      int ver_end = version_num.find("\n", ver_start);
      string version =version_num.substr(ver_start,ver_end-ver_start);
      close(sock_desc);
      return version;
  }
  else if(port == POP_PORT){
    packet_size = recv(sock_desc,packet, 1024, 0);
    string version_num(packet);
    int ver_start=version_num.find("OK");
    int ver_end=version_num.find(" ",ver_start+1);
    int ver_after=version_num.find(" ",ver_end+1);
    string version = version_num.substr(ver_end+1,ver_after-ver_end);
    close(sock_desc);
    return version;
  }
  else if(port == IMAP_PORT){
    packet_size = recv(sock_desc,packet, 1024, 0);
    string version_num(packet);
    int ver_start=version_num.find("IMAP");
    int ver_end = version_num.find(" ",ver_start+1);
    string version = version_num.substr(ver_start, ver_end-ver_start);
    close(sock_desc);
    return version;
  }
  else if(SMTP_PORT){
    packet_size = recv(sock_desc,packet, 1024, 0);
    string version_num(packet);
    int ver_start = version_num.find("P538");
    int ver_end = version_num.find(";", ver_start);
    string version = version_num.substr(ver_start, ver_end-ver_start);
    close(sock_desc);
    return version;
  }
}

/*
This returns true if a given address is a valid IPv4 address, 
and false otherwise
*/
bool valid_IP(string address){
  struct sockaddr_in addr;
  int result = inet_pton(AF_INET, address.c_str(), &(addr.sin_addr));
  if(result == 0) return false;
  else return true;
}

/*
This function takes in an IPv4 address, and a prefix

This function returns the base address of the range of addresses
*/
string find_base_addr(string address, int prefix){
  in_addr_t current_ip = inet_addr(address.c_str());
  in_addr_t ip_mask = inet_addr("255.255.255.255");
  ip_mask = ntohl(ip_mask);
  current_ip = ntohl(current_ip);
  ip_mask = ip_mask << prefix;
  current_ip = current_ip & ip_mask;
  ip_mask = htonl(ip_mask);
  current_ip = htonl(current_ip);
  struct in_addr addr;
  addr.s_addr = current_ip;
  string base_addr(inet_ntoa(addr));
  return base_addr;
}

/*
This function takes in a file name, and a vector to save to

This function reads the file line by line and saves it into
the given vector if it is a valid IPv4 address
*/
void read_ip_addr_file(const char *file_name, vector<string> *ips){
  vector<string>& ip_addresses = *ips;
  ifstream ipaddrFile(file_name);
  if(ipaddrFile.fail()){
    cout<<"File Reading Failed.\n";
    return;
  }
  else{
    string one_ip_addr;
    while(getline(ipaddrFile, one_ip_addr)){
      //Make sure it's a valid IP address before adding it
      if(valid_IP(one_ip_addr)) ip_addresses.push_back(one_ip_addr);
    }
  }
}

/*
This function takes in an IPv4 address with prefix, and a vector to save to

This function calculates the range of addresses needed and adds them to the
vector given
*/
void ip_addrs_from_prefix(const char *ip_addr, vector<string> *ips){
  vector<string>& ip_addresses = *ips;
  //Get the IP addr as a string to get prefix
  string ip_addr_prefix(ip_addr);
  int prefix_pos = ip_addr_prefix.find("/");
  prefix_pos++;

  //Use the prefix pos to get the seperate IP from prefix
  string only_ip_addr = ip_addr_prefix.substr(0,prefix_pos-1);

  //Make sure it's a valid IP address before continuing
  if(!valid_IP(only_ip_addr)){
    cout<<"Invalid IP Address given.\n";
    return;
  }

  //Now get the substring prefix and convert it to an integer
  string pref = ip_addr_prefix.substr(prefix_pos);
  int prefix = atoi(pref.c_str());
  if(prefix < 0 || prefix > 32){
    cout<<"Invalid Prefix given.\n";
    return;
  }
  prefix = NUM_OF_IPV4_BITS - prefix;

  //Get the base address given the prefix
  string base_addr = find_base_addr(only_ip_addr, prefix);
  ip_addresses.push_back(base_addr);//Add the base address to the list
  in_addr_t ip_addr_int = inet_addr(base_addr.c_str());

  //Use the prefix to determine the total number of IPs we need to add
  double num_of_addrs;
  if(prefix > 0) num_of_addrs = pow(2.0, (double) prefix);

  //Increment the base address and add the new addresses to the list
  for(int i=0; i<num_of_addrs-1; i++){
    ip_addr_int = ntohl(ip_addr_int);
    ip_addr_int++;
    ip_addr_int = htonl(ip_addr_int);
    struct in_addr addr;
    addr.s_addr = ip_addr_int;
    string ip_to_add(inet_ntoa(addr));
    ip_addresses.push_back(ip_to_add);
  }
}

/*
Reads the port names mappings file and retrieves the port names 
per port, and returns them in a vector
*/
vector<string> parse_port_names(){
  ifstream myfile("TCPPorts");
  string line;
  vector <string> portnames;
  if(!myfile){
  cout<<"Reading the Port names failed"<<endl;
  }
  else{
   while(getline(myfile,line)){
    int start =line.find(" ");
    int end= line.find("\n",start+1);
    string name=line.substr(start+2,end-start);
    portnames.push_back(name);
   }
  }
  return portnames;
}

/*
Multithreaded TCP scan function. Refer to TCP send scan for more details.
*/
void* thread_send_TCP(void * arg){
  //initializing a global temporary mutex to be used for critical sections
  // pthread_mutex_t temp_mutex;
  // pthread_mutex_init(&temp_mutex,NULL);
  // pthread_mutex_lock(&temp_mutex);
  struct temp_target *target = (struct temp_target *) arg;
  int sock_desc = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  string sourceIP = get_interface_IP(sock_desc);
  int sourcePort = random_port(65535);
  struct ps_source source;
  source.IP = sourceIP;
  source.port = sourcePort;
  send_TCP(sock_desc, source, target->IP, target->port, target->scan_type);
  // pthread_mutex_unlock(&temp_mutex);
  pthread_exit(NULL);
  close(sock_desc);
  return NULL;
}

/*
Multithreaded UDP scan function. Refer to UDP send scan for more details.
*/
void* thread_send_UDP(void * arg){
  //Initializing a global temporary mutex to be used for critical sections
  // pthread_mutex_t temp_mutex;
  // pthread_mutex_init(&temp_mutex,NULL);
  // pthread_mutex_lock(&temp_mutex);
  struct temp_target *target = (struct temp_target *)arg;
  int sock_desc = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  string sourceIP = get_interface_IP(sock_desc);
  int sourcePort = random_port(65535);
  struct ps_source source;
  source.IP = sourceIP;
  source.port = sourcePort;
  send_UDP(sock_desc,source,target->IP,target->port);
  // pthread_mutex_unlock(&temp_mutex);
  pthread_exit(NULL);
  close(sock_desc);
  return NULL;
}
