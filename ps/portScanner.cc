/***************************************************************
Authors: Ram Brundavanam & Abdulrahman Kurdi
Class: CSCI-P538 - Computer Networks
Professor: Dr. Apu Kapadia
File: portScanner.cc
Project: Port Scanner
Date Due: December 4th 2014 11:00 pm
****************************************************************/
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
 #include <iostream>
 #include <algorithm>
 #include <cmath>
 #include <string>
 #include <cstring>
 #include <sstream>
 #include <vector>
 #include <cstdlib>
 #include <fstream>
 #include <iomanip>

 #include "ps_parse.h"
 #include "ps_lib.h"

using namespace std;

int main(int argc, char * argv[]){

  //initializing random seed
  srand(time(NULL));

  //Create a Argument structure and parse the arguments into that structure
  psargs_t psargs;
  
  parse_arguments(argc, argv, &psargs);

  //Create target structures for every IP target
  vector<struct ps_targets> targets;

  //Create this source's structure
  ps_source source;

  //To get the parsed IPs, 
  vector<string> ip_file_prefix;
  vector<int> scan_ports;
  vector<string> scan_types;

  //Get all valid IP addresses from the file
  if(!psargs.file.empty()) read_ip_addr_file(psargs.file.c_str(),&ip_file_prefix);

  //Get a valid IP address from argument if available
  if(valid_IP(psargs.ip)) ip_file_prefix.push_back(psargs.ip);

  //Get all valid IP addresses from the IP prefix range
  if(!psargs.prefix.empty()) ip_addrs_from_prefix(psargs.prefix.c_str(), &ip_file_prefix);

  //If no valid IPs, quit
  if(ip_file_prefix.empty()){ 
    cout<<"No Valid IP Addresses given. Quitting.\n";
    exit(1);
  }

  //Parse the ports
  parse_comma_ports(psargs.ports, &scan_ports);

  //If no valid Ports, use defaults
  if(scan_ports.empty()){
    cout<<"No Ports specified. Using Default ports 1-1024\n";
    for(int i =1; i<1025; i++) scan_ports.push_back(i);
  }

  //Parse the scan types into Targets structure
  parse_scan_types(psargs.scan_types, &scan_types);

  //If no scan types, use all
  if(scan_types.empty()){
    //Fill the vector with all scans
    scan_types.push_back("SYN");
    scan_types.push_back("ACK");
    scan_types.push_back("NULL");
    scan_types.push_back("FIN");
    scan_types.push_back("XMAS");
    scan_types.push_back("UDP");
  }

  //Parse the port names from the file and save
  vector<string> portnames;
  portnames = parse_port_names();

  //Get the number of threads requested, max number of threads is 12
  int NUM_OF_THREADS = 1;
  if(psargs.num_of_threads > 1 && psargs.num_of_threads<13){
    NUM_OF_THREADS = psargs.num_of_threads;
  }

  //Convert the vector of scan types to a map, mapping to results
  vector<pair<string, int> > mappings;
  for(int i=0; i<scan_types.size(); i++)
    mappings.push_back(make_pair(scan_types[i],0));

  map<string, int> result_map((mappings.begin()), mappings.end());

  //Save all the parsed items into targets structure
  for(int i=0; i<ip_file_prefix.size(); i++){
    struct ps_targets current_tgt;
    current_tgt.IP = ip_file_prefix[i];
    current_tgt.ports = scan_ports;
    current_tgt.results = result_map;
    targets.push_back(current_tgt);
  }

  //Start the scan timer
  struct timeval start_time;
  struct timeval end_time;
  gettimeofday(&start_time, NULL);

  cout<<"Initializing Port Scanner."<<".."<<"..."<<"....\n";
  cout<<"Scanning...(Please wait)\n";
  vector<struct temp_target *> result_tgts;
  vector<struct temp_target> final_tgts;
  int index;
  int retransmit = 3;//Number of retransmissions
  result_tgts.reserve(targets.size()*scan_ports.size()*scan_types.size() + 1);
  //Single-threaded version
  if(NUM_OF_THREADS == 1){
    for(int i=0;i<targets.size();i++){ //For Every IP
      for(int j=0; j< targets[i].ports.size(); j++){ //For Every Port
        for(map<string,int>::iterator it = targets[i].results.begin(); it != targets[i].results.end();){

            //Create a TCP raw socket
            int tcpSock=create_raw_socket(IPPROTO_TCP);

            //Create a UDP raw socket
            int udpSock=create_raw_socket(IPPROTO_UDP);

            //Get this computer's IP where all devices will access it
            source.IP = get_interface_IP(tcpSock);

            //Get a random port number where all devices will access it
            source.port = random_port(65536);

            //Before sending, start a thread to receive
            pthread_t listen_thread;
            if(it == targets[i].results.begin()) index = 0;
            index++;
            struct temp_target temp;
            temp.IP = targets[i].IP;
            temp.port = targets[i].ports[j];
            temp.scan_type = it->first;
            temp.result = 0;
            result_tgts[index] = &temp;
            result_tgts.push_back(&temp);
            int t = pthread_create(&listen_thread, NULL, thread_sniffer, (void*) result_tgts[index]);
            sleep(1);
            //For Every Scan type, send the appropriate packet
            if(it->first == "UDP")
              send_UDP(udpSock, source, targets[i].IP, targets[i].ports[j]);
            else
              send_TCP(tcpSock, source, targets[i].IP, targets[i].ports[j], it->first);
            //Wait for the sniffer to sniff the appropriate packets, then send a cancel signal
            sleep(1);
            pthread_cancel(listen_thread);
            //Let the parent thread wait for the child
            pthread_join(listen_thread, NULL);
            struct temp_target final_tgt;
            final_tgt.IP = result_tgts[index]->IP;
            final_tgt.port = result_tgts[index]->port;
            final_tgt.scan_type = result_tgts[index]->scan_type;
            final_tgt.result = result_tgts[index]->result;

            //Close the sockets
            close(tcpSock);
            close(udpSock);
            //If we didn't get anything, retransmit
            if(result_tgts[index]->result == 0 && retransmit > 0){
              sleep(3);
              retransmit--;
            }
            else{ 
              //No response case
              if(retransmit == 0 && result_tgts[index]->result == 0){
                if(final_tgt.scan_type == "SYN") final_tgt.result = 3;//filtered
                else if(final_tgt.scan_type == "ACK") final_tgt.result = 3;//filtered
                else if(final_tgt.scan_type == "NULL" || final_tgt.scan_type == "FIN" || final_tgt.scan_type == "XMAS")
                  final_tgt.result = 5; //open|filtered
                else if(final_tgt.scan_type == "UDP") final_tgt.result = 5;//open|filtered
              }
              final_tgts.push_back(final_tgt); 
              ++it;
              retransmit = 3;//reinitialize the retransmissions for next one
            }
        }
      }
      result_tgts[i] = NULL;
    }
  }
  else{
    //Multithreaded version
    pthread_t sending_threads[NUM_OF_THREADS];
    for(int i=0;i<targets.size();i++){ //For Every IP
      for(int j=0; j< targets[i].ports.size(); j++){ //For Every Port
        for(map<string,int>::iterator it = targets[i].results.begin(); it != targets[i].results.end();){
            if(it == targets[i].results.begin()) index = 0;        
            struct temp_target temp;
            temp.IP = targets[i].IP;
            temp.port = targets[i].ports[j];
            temp.scan_type = it->first;
            temp.result = 0;
            pthread_t listen_thread;
            int thread1=pthread_create(&listen_thread,NULL,thread_sniffer,(void *)&temp);
            sleep(0.5);
            result_tgts[index] = &temp;            
            result_tgts.push_back(&temp);
            if(temp.scan_type=="UDP"){
             int k = pthread_create(&sending_threads[index], NULL,thread_send_UDP, (void *)&temp);
            }
            else{
             int k = pthread_create(&sending_threads[index], NULL,thread_send_TCP, (void *)&temp);          
            }
            int rc = pthread_join(sending_threads[index], NULL);
            index++;
            sleep(1);
            pthread_cancel(listen_thread);
            pthread_join(listen_thread,NULL);
            struct temp_target final_tgt;
            final_tgt.IP = temp.IP;
            final_tgt.port = temp.port;
            final_tgt.scan_type = temp.scan_type;
            final_tgt.result = temp.result;
           
            //If we didn't get anything, retransmit
            if(temp.result == 0 && retransmit > 0){
              sleep(3);
              retransmit--;
            }
            else{ 
              //No response case
              if(retransmit == 0 && temp.result == 0){
                if(final_tgt.scan_type == "SYN") final_tgt.result = 3;//filtered
                else if(final_tgt.scan_type == "ACK") final_tgt.result = 3;//filtered
                else if(final_tgt.scan_type == "NULL" || final_tgt.scan_type == "FIN" || final_tgt.scan_type == "XMAS")
                  final_tgt.result = 5; //open|filtered
                else if(final_tgt.scan_type == "UDP") final_tgt.result = 5;//open|filtered
              }
              final_tgts.push_back(final_tgt); 
              ++it;
              retransmit = 3;//reinitialize the retransmissions for next one
            }
        }
      }
    }
  }

  //Get the end time, and calculate program running time
  gettimeofday(&end_time, NULL);
  double scan_time; 
  scan_time = (end_time.tv_sec - start_time.tv_sec)*1000000L;
  scan_time += end_time.tv_usec;
  scan_time -= start_time.tv_usec;
  scan_time = scan_time / 1000000L;
  cout<<"The Scan took: "<<scan_time<<" Seconds"<<endl;

  int num_of_scans_per_ip = final_tgts.size()/targets.size();
  cout<<"\t \t \t \t \t \t****PORT SCANNER****\n";
  for(int i=0; i< final_tgts.size(); i++){
    string result;
    if(final_tgts[i].result == 1) result = "Open";
    else if(final_tgts[i].result == 2) result = "Closed";
    else if(final_tgts[i].result == 3) result = "Filtered";
    else if(final_tgts[i].result == 4) result = "Unfiltered";
    else if(final_tgts[i].result == 5) result = "Open | Filtered";
    if((i % num_of_scans_per_ip) == 0){
      cout<<"\n======================================================================================\n";
      cout<<"IP Address: "<<final_tgts[i].IP<<endl;
    }
    if(i % scan_types.size() == 0) 
      cout<<"----------------------------------------------------------------------------------------\n";
    cout<<"Port: "<<final_tgts[i].port<<"("<<portnames[final_tgts[i].port]<<")"<<"\t \t \t \t "<<final_tgts[i].scan_type<<" SCAN(";
    cout<<result<<")\n";
  }

  //Check the results, and form a conclusion per IP/Port pair
  decide_status(final_tgts, scan_types);

  vector<string> checked_IPs;
  vector<int> checked_ports;
  bool used_IP;
  bool used_Port;
  //Check to see if we should verify
  bool verification_required = false;
  for(int i=0; i<scan_ports.size(); i++){
    if(scan_ports[i] == 22 || scan_ports[i] == 24 || scan_ports[i] == 25 || scan_ports[i] == 587 || scan_ports[i] == 43 || scan_ports[i] == 80 || scan_ports[i] == 110 || scan_ports[i] == 143)
      verification_required = true;
  }

  //Verify the ports
  if(verification_required){
    cout<<"Verification of Services\n";
    cout<<"-------------------------";
    for(int i=0; i< final_tgts.size(); i++){
      used_IP = false;
      used_Port = false;
      if(final_tgts[i].result == 1 && !used_Port && !used_IP){
        if(final_tgts[i].port == 22){
          cout<<"\nSSH Service running on port "<<final_tgts[i].port;
          cout<<" at IP "<<final_tgts[i].IP<<" is ";
          cout<<verify_services(final_tgts[i].IP ,final_tgts[i].port)<<endl;
          checked_IPs.push_back(final_tgts[i].IP);
          checked_ports.push_back(final_tgts[i].port);
        }
        else if(final_tgts[i].port == 80){
          
          cout<<"\nHTTP Service running on port "<<final_tgts[i].port;
          cout<<" at IP "<<final_tgts[i].IP<<" is ";
          cout<<verify_services(final_tgts[i].IP ,final_tgts[i].port)<<endl;
          checked_IPs.push_back(final_tgts[i].IP);
          checked_ports.push_back(final_tgts[i].port);
        }
        else if(final_tgts[i].port == 110){
 
          cout<<"\nPOP3 Service running on port "<<final_tgts[i].port;
          cout<<" at IP "<<final_tgts[i].IP<<" is ";
          cout<<verify_services(final_tgts[i].IP ,final_tgts[i].port)<<endl;
          checked_IPs.push_back(final_tgts[i].IP);
          checked_ports.push_back(final_tgts[i].port);
        }
        else if(final_tgts[i].port == 143){

          cout<<"\nIMAP Service running on port "<<final_tgts[i].port;
          cout<<" at IP "<<final_tgts[i].IP<<" is ";
          cout<<verify_services(final_tgts[i].IP ,final_tgts[i].port)<<endl;
          checked_IPs.push_back(final_tgts[i].IP);
          checked_ports.push_back(final_tgts[i].port);
        }
        else if(final_tgts[i].port == 24 || final_tgts[i].port == 25 || final_tgts[i].port == 587){

          cout<<"\nSMTP Service running on port "<<final_tgts[i].port;
          cout<<" at IP "<<final_tgts[i].IP<<" is ";
          cout<<verify_services(final_tgts[i].IP ,final_tgts[i].port)<<endl;
          checked_IPs.push_back(final_tgts[i].IP);
          checked_ports.push_back(final_tgts[i].port);
        }
        else if(final_tgts[i].port == 43){
          
          cout<<"\nWHOIS Service running on port "<<final_tgts[i].port;
          cout<<" at IP "<<final_tgts[i].IP<<" is ";
          cout<<verify_services(final_tgts[i].IP ,final_tgts[i].port)<<endl;
          checked_IPs.push_back(final_tgts[i].IP);
          checked_ports.push_back(final_tgts[i].port);
        }
      }
    }
  }
  return 0;
}
